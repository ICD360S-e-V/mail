// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/io_client.dart';
import 'certificate_expiry_monitor.dart';
import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'pinned_security_context.dart';

/// Service for downloading per-user certificates from server
/// Eliminates hardcoded certificates vulnerability
class CertificateService {

  /// Downloaded certificates (stored in memory only)
  // SECURITY (M7): in-memory cache of the per-user mTLS certificate.
  // This cache is populated at login (DeviceApprovalService) and
  // refilled from [_secureStorage] after each lock/unlock cycle. The
  // cache is intentionally NOT static-final and IS cleared by
  // [lockCache] so a process heap dump captured outside an active
  // unlocked session does not reveal the private key. The
  // authoritative copy lives in the platform's secure storage
  // (Android Keystore-protected EncryptedSharedPreferences, iOS
  // Keychain, Windows DPAPI Credential Manager, macOS Keychain,
  // Linux libsecret) so it survives process restarts without ever
  // being touched by the public filesystem.
  static Uint8List? _clientCert;
  static Uint8List? _clientKey;
  static Uint8List? _caCert;
  static String? _currentUsername;

  // Storage backend for cert/key/CA: MasterVault on macOS (B5,
  // v2.30.0+) which is locked behind the user's master password via
  // Argon2id+HKDF+AES-GCM. On iOS/Android/Windows/Linux MasterVault
  // is a thin pass-through to PortableSecureStorage which itself
  // delegates to flutter_secure_storage (Keychain / Keystore /
  // DPAPI / libsecret) — already password/biometric-protected at
  // the OS level.
  //
  // The legacy `secure_store.bin` migration is handled inside
  // MasterVault.unlock() — the first successful unlock after upgrade
  // moves the cert/key/CA out of PortableSecureStorage into the
  // master-pwd-protected vault, then deletes them from the legacy
  // store.
  static final _secureStorage = MasterVault.instance;

  // Per-username storage keys (v2.30.2+).
  // The pre-v2.30.2 storage used GLOBAL keys without a username
  // suffix, which broke when the user added a SECOND Faza 3 account:
  // the second cert overwrote the first, and the first account
  // could never restore its cert. Migration is handled at the
  // start of restoreFromSecureStorage().
  //
  // v2.30.3 hotfix: the original v2.30.2 layout used `::$username`
  // directly, with `:` and `@` characters (e.g.
  // `icd360s_mtls_client_cert::in@icd360s.de`). This caused
  // flutter_secure_storage to fail silently on iOS Keychain (the
  // Faza 3 cert install dialog hung forever on "Approved!
  // Downloading…"). The new layout sanitizes the username to only
  // [a-zA-Z0-9._-]. A best-effort migration in
  // [_migrateUnsafeUserKeys] copies any successfully-stored v2.30.2
  // entries into the safe format.
  static String _safeUserSuffix(String username) =>
      username.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
  static String _kStorageClientCertFor(String username) =>
      'icd360s_mtls_client_cert_${_safeUserSuffix(username)}';
  static String _kStorageClientKeyFor(String username) =>
      'icd360s_mtls_client_key_${_safeUserSuffix(username)}';
  static String _kStorageCaCertFor(String username) =>
      'icd360s_mtls_ca_cert_${_safeUserSuffix(username)}';

  // v2.30.2 unsafe key format (kept for one-time migration only).
  static String _unsafeKStorageClientCertFor(String username) =>
      'icd360s_mtls_client_cert::$username';
  static String _unsafeKStorageClientKeyFor(String username) =>
      'icd360s_mtls_client_key::$username';
  static String _unsafeKStorageCaCertFor(String username) =>
      'icd360s_mtls_ca_cert::$username';

  // Legacy global keys (v2.27.0 — v2.30.1) — used only for one-time
  // migration into the per-username keys above.
  static const String _kStorageClientCertLegacy = 'icd360s_mtls_client_cert';
  static const String _kStorageClientKeyLegacy = 'icd360s_mtls_client_key';
  static const String _kStorageCaCertLegacy = 'icd360s_mtls_ca_cert';
  static const String _kStorageUsernameLegacy = 'icd360s_mtls_username';

  // Registry of usernames that have a cert in secure storage. Allows
  // [clearCertificates] (factory reset / explicit logout) to wipe ALL
  // per-user entries without scanning the entire keystore.
  static const String _kKnownCertUsernames = 'icd360s_mtls_known_cert_users';

  /// Append [username] to the known-users JSON list (idempotent).
  static Future<void> _registerKnownUser(String username) async {
    try {
      final raw = await _secureStorage.read(key: _kKnownCertUsernames);
      final List<dynamic> list =
          raw == null || raw.isEmpty ? <dynamic>[] : (jsonDecode(raw) as List);
      if (!list.contains(username)) {
        list.add(username);
        await _secureStorage.write(
            key: _kKnownCertUsernames, value: jsonEncode(list));
      }
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Read the known-users registry. Returns empty list on error.
  static Future<List<String>> _getKnownUsers() async {
    try {
      final raw = await _secureStorage.read(key: _kKnownCertUsernames);
      if (raw == null || raw.isEmpty) return <String>[];
      return (jsonDecode(raw) as List).cast<String>();
    } catch (_) {
      return <String>[];
    }
  }

  /// Track if network is down to avoid spamming all accounts
  static bool _networkDown = false;

  /// Validate server certificate — only accept trusted Let's Encrypt issuers.
  /// Uses the shared `isTrustedLetsEncryptIssuer` helper which parses the
  /// slash-format DN that Dart returns from X509Certificate.issuer.
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    return isTrustedLetsEncryptIssuer(cert.issuer);
  }

  /// Check if network/DNS is working before batch operations
  static Future<bool> isNetworkAvailable() async {
    try {
      final result = await InternetAddress.lookup('mail.icd360s.de')
          .timeout(const Duration(seconds: 5));
      _networkDown = result.isEmpty;
      return result.isNotEmpty;
    } catch (_) {
      _networkDown = true;
      return false;
    }
  }

  /// Whether network was detected as down
  static bool get isNetworkDown => _networkDown;

  /// Get downloaded client certificate bytes (or null if not downloaded)
  static Uint8List? get clientCert => _clientCert;

  /// Get downloaded client key bytes (or null if not downloaded)
  static Uint8List? get clientKey => _clientKey;

  /// Get downloaded CA certificate bytes (or null if not downloaded)
  static Uint8List? get caCert => _caCert;

  /// Get current username for downloaded certificate
  static String? get currentUsername => _currentUsername;

  /// Check if certificates are available in memory
  static bool get hasCertificates =>
      _clientCert != null && _clientKey != null && _caCert != null;

  /// Persist a cert bundle obtained out-of-band (Faza 3 / device
  /// approval flow) under the per-username keys, register the user
  /// in the known-users registry, and load it into the in-memory
  /// cache. This is the single entry point for code that already
  /// has cert/key/CA in hand and just needs to store it.
  static Future<void> storeBundle({
    required String username,
    required String clientCert,
    required String clientKey,
    required String caCert,
  }) async {
    await _secureStorage.write(
        key: _kStorageClientCertFor(username), value: clientCert);
    await _secureStorage.write(
        key: _kStorageClientKeyFor(username), value: clientKey);
    await _secureStorage.write(
        key: _kStorageCaCertFor(username), value: caCert);
    await _registerKnownUser(username);
    _clientCert = Uint8List.fromList(utf8.encode(clientCert));
    _clientKey = Uint8List.fromList(utf8.encode(clientKey));
    _caCert = Uint8List.fromList(utf8.encode(caCert));
    _currentUsername = username;
    // Persist real expiry parsed from the cert PEM.
    try {
      await CertificateExpiryMonitor.parseCertAndPersistExpiry(clientCert);
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
    LoggerService.log('CERT-DOWNLOAD',
        'Cert bundle stored for $username (per-username keys)');
  }

  /// Clear the in-memory certificate cache only (auto-lock path).
  ///
  /// SECURITY (M7): Called when the master-password session is
  /// auto-locked. Removes references to the PEM strings so the next
  /// garbage-collection cycle wipes them from the Dart heap. The
  /// authoritative copy in [_secureStorage] is left alone so the
  /// next [restoreFromSecureStorage] call after unlock can repopulate
  /// the cache without re-downloading from the server.
  static void lockCache() {
    if (_clientCert == null && _clientKey == null && _caCert == null) {
      return;
    }
    if (_clientKey != null) {
      for (var i = 0; i < _clientKey!.length; i++) _clientKey![i] = 0;
    }
    if (_clientCert != null) {
      for (var i = 0; i < _clientCert!.length; i++) _clientCert![i] = 0;
    }
    if (_caCert != null) {
      for (var i = 0; i < _caCert!.length; i++) _caCert![i] = 0;
    }
    _clientCert = null;
    _clientKey = null;
    _caCert = null;
    _currentUsername = null;
    LoggerService.log('CERT-DOWNLOAD',
        'mTLS cert cache cleared from memory (lock)');
  }

  /// v2.30.3 hotfix migration: copy any successfully-stored v2.30.2
  /// `::user@host` entries into the new sanitized key format. Best
  /// effort — silently skips if the v2.30.2 keys don't exist (which is
  /// the common case, since the v2.30.2 write usually FAILED on iOS
  /// and never persisted anything). Idempotent.
  static Future<void> _migrateUnsafeUserKeys(String username) async {
    try {
      final cert = await _secureStorage
          .read(key: _unsafeKStorageClientCertFor(username));
      final key = await _secureStorage
          .read(key: _unsafeKStorageClientKeyFor(username));
      final ca = await _secureStorage
          .read(key: _unsafeKStorageCaCertFor(username));
      if (cert == null || key == null || ca == null) return;
      await _secureStorage.write(
          key: _kStorageClientCertFor(username), value: cert);
      await _secureStorage.write(
          key: _kStorageClientKeyFor(username), value: key);
      await _secureStorage.write(
          key: _kStorageCaCertFor(username), value: ca);
      await _secureStorage.delete(key: _unsafeKStorageClientCertFor(username));
      await _secureStorage.delete(key: _unsafeKStorageClientKeyFor(username));
      await _secureStorage.delete(key: _unsafeKStorageCaCertFor(username));
      LoggerService.log('CERT-DOWNLOAD',
          'Migrated v2.30.2 unsafe per-user keys → safe format for $username');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// One-time migration: if the legacy global keys still hold a cert
  /// (v2.27.0 — v2.30.1 layout), copy it under the per-username keys
  /// for the legacy username and delete the global entries. Idempotent.
  ///
  /// Multi-account note: the legacy layout could only ever hold ONE
  /// cert (the most-recently-downloaded one). After migration, the
  /// "first" account on this device gets its cert restored; any other
  /// Faza 3 accounts must re-trigger the approval flow on their first
  /// post-upgrade login (which will then write under per-user keys
  /// and stay isolated).
  static Future<void> _migrateLegacyGlobalKeys() async {
    try {
      final legacyUser = await _secureStorage.read(key: _kStorageUsernameLegacy);
      if (legacyUser == null || legacyUser.isEmpty) return;
      final cert = await _secureStorage.read(key: _kStorageClientCertLegacy);
      final key = await _secureStorage.read(key: _kStorageClientKeyLegacy);
      final ca = await _secureStorage.read(key: _kStorageCaCertLegacy);
      if (cert == null || key == null || ca == null) {
        // Partial legacy state — just clean it up.
        await _secureStorage.delete(key: _kStorageClientCertLegacy);
        await _secureStorage.delete(key: _kStorageClientKeyLegacy);
        await _secureStorage.delete(key: _kStorageCaCertLegacy);
        await _secureStorage.delete(key: _kStorageUsernameLegacy);
        return;
      }
      await _secureStorage.write(
          key: _kStorageClientCertFor(legacyUser), value: cert);
      await _secureStorage.write(
          key: _kStorageClientKeyFor(legacyUser), value: key);
      await _secureStorage.write(
          key: _kStorageCaCertFor(legacyUser), value: ca);
      await _registerKnownUser(legacyUser);
      await _secureStorage.delete(key: _kStorageClientCertLegacy);
      await _secureStorage.delete(key: _kStorageClientKeyLegacy);
      await _secureStorage.delete(key: _kStorageCaCertLegacy);
      await _secureStorage.delete(key: _kStorageUsernameLegacy);
      LoggerService.log('CERT-DOWNLOAD',
          'Migrated legacy global mTLS cert keys → per-username keys for $legacyUser');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Repopulate the in-memory cache from [_secureStorage] for a
  /// SPECIFIC user (v2.30.2+).
  ///
  /// SECURITY (M7): Called by EmailProvider when (re)connecting an
  /// account so each account loads its own per-username cert. The
  /// in-memory cache holds at most one cert at a time — switching to
  /// a different user replaces it.
  ///
  /// Multi-account: this is the correct entry point for code that
  /// knows which account it wants. The legacy [restoreFromSecureStorage]
  /// (no username) is preserved only for the master-password unlock
  /// path which has no account context.
  static Future<bool> restoreFromSecureStorageFor(String username) async {
    if (_currentUsername == username && hasCertificates) return true;
    try {
      // Run legacy migration first so a freshly upgraded user with the
      // old global keys can still be restored under the new layout.
      await _migrateLegacyGlobalKeys();
      // v2.30.3: also migrate from v2.30.2 unsafe `::user@host` keys.
      await _migrateUnsafeUserKeys(username);

      final cert = await _secureStorage.read(key: _kStorageClientCertFor(username));
      final key = await _secureStorage.read(key: _kStorageClientKeyFor(username));
      final ca = await _secureStorage.read(key: _kStorageCaCertFor(username));
      if (cert == null || key == null || ca == null) {
        return false;
      }
      _clientCert = Uint8List.fromList(utf8.encode(cert));
      _clientKey = Uint8List.fromList(utf8.encode(key));
      _caCert = Uint8List.fromList(utf8.encode(ca));
      _currentUsername = username;
      // Restore persisted expiry dates (parsed from PEM at download time)
      await CertificateExpiryMonitor.loadPersistedExpiry();
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert cache restored from secure storage for $username');
      return true;
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
      return false;
    }
  }

  /// Best-effort restore at master-password unlock time, when no
  /// account context is available yet.
  ///
  /// Tries (in order):
  ///   1. Legacy global key migration (populates per-username keys).
  ///   2. The first known user from the registry — so the in-memory
  ///      cache is non-empty and the IMAP/SMTP layer can establish
  ///      the initial connection. EmailProvider will subsequently
  ///      call [restoreFromSecureStorageFor] per account to swap in
  ///      the correct cert before each connect.
  static Future<bool> restoreFromSecureStorage() async {
    if (hasCertificates) return true;
    try {
      await _migrateLegacyGlobalKeys();
      final users = await _getKnownUsers();
      if (users.isEmpty) return false;
      return await restoreFromSecureStorageFor(users.first);
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
      return false;
    }
  }

  /// Clear certificates from BOTH memory cache AND persistent secure
  /// storage (explicit logout / sign-out / factory reset).
  ///
  /// After this call, the next session must re-download the cert via
  /// [DeviceApprovalService.downloadCert]. Use [lockCache] for the auto-lock
  /// path that should preserve the secure-storage copy.
  ///
  /// v2.30.2: iterates the known-users registry so every per-username
  /// cert triple is wiped, then deletes the registry itself and the
  /// legacy global keys for backward compatibility.
  static Future<void> clearCertificates() async {
    lockCache();
    try {
      final users = await _getKnownUsers();
      for (final u in users) {
        await _secureStorage.delete(key: _kStorageClientCertFor(u));
        await _secureStorage.delete(key: _kStorageClientKeyFor(u));
        await _secureStorage.delete(key: _kStorageCaCertFor(u));
      }
      await _secureStorage.delete(key: _kKnownCertUsernames);
      // Legacy global keys (pre-v2.30.2) — defensive cleanup.
      await _secureStorage.delete(key: _kStorageClientCertLegacy);
      await _secureStorage.delete(key: _kStorageClientKeyLegacy);
      await _secureStorage.delete(key: _kStorageCaCertLegacy);
      await _secureStorage.delete(key: _kStorageUsernameLegacy);
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert wiped from secure storage (explicit logout, ${users.length} users)');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Clear cert for a SINGLE user (used when one account is removed
  /// from the app while others remain). Does not touch the in-memory
  /// cache unless it currently belongs to [username].
  static Future<void> clearCertificatesFor(String username) async {
    if (_currentUsername == username) lockCache();
    try {
      await _secureStorage.delete(key: _kStorageClientCertFor(username));
      await _secureStorage.delete(key: _kStorageClientKeyFor(username));
      await _secureStorage.delete(key: _kStorageCaCertFor(username));
      // Remove from known-users registry.
      final users = await _getKnownUsers();
      users.remove(username);
      if (users.isEmpty) {
        await _secureStorage.delete(key: _kKnownCertUsernames);
      } else {
        await _secureStorage.write(
            key: _kKnownCertUsernames, value: jsonEncode(users));
      }
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert wiped from secure storage for $username');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }
}