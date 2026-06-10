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
| `lib/services/master_vault.dart`                | patched (see §1 + §2)        |
| `lib/services/master_password_service.dart`     | patched (see §3)             |
| `lib/services/pgp_key_service.dart`             | patched (see "Second layer" below)  |

---

# Second layer: passphrase-in-blob (v2 sync format)

Salt-sync alone is **necessary but not sufficient** for multi-device PGP.

The blob KEK (HKDF on master key) is now the same on every device, so
`PgpSyncService` returns the correct plaintext from the server blob.
But the OpenPGP armor inside is *also* protected with an S2K
passphrase, and `PgpKeyService._getOrCreatePassphrase()` originally
generated a **per-device random** stored in the local vault. Device B
would derive the same blob KEK as Device A, unwrap the blob, and then
fail to S2K-decrypt the inner armored key because its local random
differed from Device A's. The fallback path generated a fresh keypair
and overwrote the public key on the server — at which point every
historical mail became unreadable.

## How the industry handles this

- **ProtonMail**: `/api/auth` returns `{User.Keys, KeySalts}`. The
  client computes `passphrase = bcrypt(rawPassword, KeySalt)` and
  decrypts the armored private key with that passphrase. The
  passphrase derivation is deterministic, so the same `(password,
  KeySalt)` produces the same passphrase on every device. The salt is
  stored on the server in a separate field next to the encrypted key.

- **Tutanota (TutaCrypt)**: private key is encrypted with the user's
  password (Argon2 + SHA256 derivation), encrypted blob shipped to
  the server, every device pulls the blob and decrypts with the
  derived passphrase.

- **Bitwarden**: master password → PBKDF2 (600k) → Master Key → HKDF
  → Stretched Master Key. A random Symmetric Key wraps everything in
  the vault (including the OpenPGP-style private key); the Symmetric
  Key itself is wrapped by the Stretched Master Key as the
  "Protected Symmetric Key" stored on the server. Every device
  downloads the Protected Symmetric Key, unwraps with the local
  Stretched Master Key, and now has the Symmetric Key needed to
  decrypt the rest.

All three patterns share the same property: **everything a fresh
device needs to recover the private key can be derived from `(master
password, server-supplied data)`**. No per-device random survives.

## What we ship

We adopt the Bitwarden-style "the blob carries the wrapping key"
pattern, scaled to a single self-contained envelope.

The blob plaintext is a JSON object with three fields: a format
version (`v` = 2), the S2K passphrase used to wrap the OpenPGP
private key (an opaque random hex string), and the armored OpenPGP
private key itself. The whole plaintext is then sealed with AES-GCM
under the blob KEK:

```
blob ciphertext = AES-GCM(plaintext, blobKEK, AAD = "v<version>|<email>")
blobKEK         = HKDF-SHA256(masterKey, info="pgp-blob-kek-v1", ...)
masterKey       = Argon2id(masterPassword, server-bound salt)
```

The S2K passphrase is a per-account random — but it lives **inside**
the blob, not in any device's local vault. A fresh device:

1. enters the master password,
2. fetches the server-bound Argon2id salt → derives `masterKey`,
3. derives `blobKEK` via HKDF,
4. downloads the blob and decrypts → recovers `{passphrase, armor}`,
5. uses `passphrase` to unwrap `armor`.

No re-armoring, no HKDF-derived passphrase, no migration of the OpenPGP
keypair itself. The passphrase travels with the armor. Every device
that knows the master password can recover everything.

## Migration from v1 (armor-only) to v2 (self-contained)

Existing users today have a v1 blob on the server (just an
AES-GCM-wrapped armor) plus a per-device random passphrase in the
local vault. On first launch with the new client:

1. Local-key load path decrypts the armor with the local passphrase
   (legacy path, unchanged).
2. `_ensureServerHasV2Blob` runs in the background: fetches the
   current server blob, sees it's v1 (or missing), and uploads a v2
   blob assembled from `{local passphrase, existing armor}`.
3. Future fresh-device installs download the v2 blob and decrypt
   zero-touch.

If the server already has a v2 blob, `_ensureServerHasV2Blob` is a
no-op (idempotent).

## Hard guarantees and failure modes

The fresh-device "download blob → can't decrypt → generate new key"
path is **disabled**. Generating a new key in that state would publish
a different public key to the server and overwrite the existing blob,
destroying every historical mail to that address. So when a device
finds a blob on the server it cannot unwrap, it now throws a
`StateError` instead of falling through.

| State                                                                                          | Behavior                                          |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **v2 self-contained blob on server**                                                           | Decrypts, persists passphrase + armor locally, returns. **Zero-touch.**     |
| **v1 (armor-only) blob on server, this device has no matching passphrase**                     | Throws `StateError` — relaunch on originating device to upgrade blob to v2 |
| **No blob on server**                                                                          | Generates a fresh keypair (first-device path), uploads as v2 |
| **Blob on server, KEK decrypt fails (master vault salt mismatch, network)**                    | Logs warning, **does** fall through to fresh-key gen as a last resort |

The bootstrap-order constraint applies *only* to the second row —
the user with an existing v1 blob and a fresh new device. Once any
existing device has launched the updated app once, the server has a
v2 blob and every subsequent fresh-device install works zero-touch.

## Recovery limitations (be honest)

If a user owns exactly one device, that device is destroyed, and the
sync server still has only the v1 blob (no device ever ran the new
client), the user cannot recover their PGP key. The legacy passphrase
was per-device random, was never derivable from the master password,
and the new device has no way to reproduce it from anything on the
server. Reset via `DELETE /api/pgp-blob.php` is the only option, and
every historical mail to that address becomes unreadable.

For this reason, the rollout window should be as short as possible.
Once every existing device has launched the new client once (which
upgrades the blob to v2), fresh installs work zero-touch forever after.
