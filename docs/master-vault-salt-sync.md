# Master Vault salt sync — integration guide

This document describes the changes needed to wire the new
`MasterVaultMetaService` into the existing vault-creation flow so that
the same master password derives the **same** master key on every
device of a user — the missing piece that made `PgpSyncService` blobs
unreadable on a fresh install of a second device.

## What was added (already shipped)

| Layer  | Component                                                    |
| ------ | ------------------------------------------------------------ |
| Server | `/api/master-vault-meta.php`                                 |
|        | `/var/lib/master-vault-meta/` (perms 700, owner apache)      |
|        | nginx `location = /api/master-vault-meta.php` block          |
|        | PHP `open_basedir` + systemd `ReadWritePaths` updated        |
| Client | `lib/services/master_vault_meta_service.dart`                |

The endpoint is tested end-to-end (GET 404 → POST 201 → GET 200 → POST 409
→ POST 400 with wrong length) and live.

## What still needs a patch (NOT yet applied)

Two call sites in `lib/services/master_vault.dart` create a vault with a
random local salt and never consult the server. Both should be wrapped
to first try `MasterVaultMetaService.fetchOrBindSalt`.

The `email` (account username used to identify the user on the server)
must be passed in — it is *not* available inside `MasterVault` today.
The simplest, lowest-risk way to thread it through is to add a new
public method that takes `boundEmail` and have the entry-point caller
(`MasterPasswordService.unlock` / wherever the initial unlock happens)
pass it.

### 1. New helper inside `_createFreshVault`

Today (`master_vault.dart`):

```dart
Future<void> _createFreshVault(String pwd) async {
  final s = sodium!;
  _cache = {};
  _dataKey = s.secureRandom(_dataKeyBytes);
  _argon2Salt = _randomBytes(_argon2SaltBytes);
  final vaultMasterKey = await deriveMasterKey(pwd, _argon2Salt!);
  _kek = await _deriveKEKFromMasterKeyBytes(vaultMasterKey);
  for (var i = 0; i < vaultMasterKey.length; i++) vaultMasterKey[i] = 0;
}
```

Proposed:

```dart
Future<void> _createFreshVault(String pwd, {String? boundEmail}) async {
  final s = sodium!;
  _cache = {};
  _dataKey = s.secureRandom(_dataKeyBytes);

  // Generate a local random salt as the offline fallback…
  Uint8List salt = _randomBytes(_argon2SaltBytes);

  // …but if we know which email this vault is for, try to align with the
  // server-bound salt so this device produces the same master key as
  // every other device of the same user.
  if (boundEmail != null) {
    final remote = await MasterVaultMetaService.fetchOrBindSalt(
      email: boundEmail,
      localFallback: salt,
    );
    if (remote != null) {
      salt = remote;
    }
    // remote == null → network error; keep local salt and try again next unlock.
  }

  _argon2Salt = salt;
  final vaultMasterKey = await deriveMasterKey(pwd, _argon2Salt!);
  _kek = await _deriveKEKFromMasterKeyBytes(vaultMasterKey);
  for (var i = 0; i < vaultMasterKey.length; i++) vaultMasterKey[i] = 0;
}
```

### 2. New public entry point on `MasterVault`

```dart
Future<void> unlockBoundTo(String masterPassword, String boundEmail) async {
  if (isUnlocked) return;
  if (_unlocking) return;
  _unlocking = true;
  _assertSodium();
  try {
    final path = await _path();
    final file = File(path);
    if (!await file.exists()) {
      await _createFreshVault(masterPassword, boundEmail: boundEmail);
      await _runMigrationFromLegacyStorage();
      await _persist();
      return;
    }
    // Existing vault on disk: standard unlock path. Its salt was set when
    // the file was first created — we don't try to re-bind it.
    final blob = await file.readAsBytes();
    if (blob[0] == _formatVersion) {
      await _loadAndDecryptV4(blob, masterPassword);
    } else if (blob[0] == _legacyV3FormatVersion) {
      await _migrateFromV3(blob, masterPassword);
    } else {
      throw StateError('Unknown vault format: 0x${blob[0].toRadixString(16)}');
    }
    if (!_migrationDone) {
      await _runMigrationFromLegacyStorage();
      if (_migrationDone) await _persist();
    }
  } finally {
    _unlocking = false;
  }
}
```

The classic `unlock(masterPassword)` (no `boundEmail`) stays unchanged
for callers that don't yet know the account — e.g. the legacy first-boot
path.

### 3. Caller change in `MasterPasswordService`

Around `lib/services/master_password_service.dart:440`, the call

```dart
await MasterVault.instance.unlock(password);
```

becomes

```dart
final email = primaryAccountEmail;  // whatever resolves to the bound email
if (email != null) {
  await MasterVault.instance.unlockBoundTo(password, email);
} else {
  await MasterVault.instance.unlock(password);
}
```

The "primary account" question is the only product decision: pick the
first account ever enrolled on this device (preferred), the currently
selected/active account, or expose a UI choice. Whichever it is, the
**same email** must be used across all of that user's devices — that's
the whole point.

## Operational notes

- **First-write-wins on the server**: once a user has bound a salt, the
  endpoint refuses to overwrite it (HTTP 409). To rotate a salt the
  admin must `rm /var/lib/master-vault-meta/<username>.json` — but that
  also invalidates every `PgpSyncService` blob the user has, so old
  encrypted mail becomes unreadable. This is the same lifetime as the
  PGP blob itself.

- **Network errors are non-fatal**: `fetchOrBindSalt` returns `null` on
  network/protocol errors so vault creation is never blocked. The next
  unlock will re-attempt the sync.

- **Existing users with a working vault are not affected**: the patch
  only runs at *fresh* vault creation (`!file.exists()`). Anyone whose
  vault file already exists keeps their current salt — its
  fingerprint is locked into the file itself.

- **Bootstrapping existing users**: if you want to back-fill the bound
  salt for the ~10 users who already have a working blob, the simplest
  path is to have the client POST the salt on next unlock when the
  server doesn't have one yet (essentially what `fetchOrBindSalt`
  already does). No admin action needed.

## Files changed (server)

Backup root: `/root/master-vault-meta-20260607-121733/` on `mail` VM.

| File on server                                         | Change                                  |
| ------------------------------------------------------ | --------------------------------------- |
| `/var/www/html/api/master-vault-meta.php`              | **NEW**                                 |
| `/var/lib/master-vault-meta/`                          | **NEW directory** (apache:apache, 700)  |
| `/etc/php.ini`                                         | added path to `open_basedir`            |
| `/etc/systemd/system/php-fpm.service.d/hardening.conf` | added path to `ReadWritePaths`          |
| `/etc/nginx/conf.d/mail.icd360s.de.conf`               | added `location = /api/master-vault-meta.php` block |

## Files changed (client)

| File                                            | Change                       |
| ----------------------------------------------- | ---------------------------- |
| `lib/services/master_vault_meta_service.dart`   | **NEW**                      |
| `lib/services/master_vault.dart`                | *Patch not yet applied — see §1 + §2* |
| `lib/services/master_password_service.dart`    | *Patch not yet applied — see §3*     |
