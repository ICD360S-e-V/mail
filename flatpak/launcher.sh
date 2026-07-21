#!/bin/bash
# Wrapper that starts gnome-keyring-daemon inside the sandbox before
# handing off to the Flutter binary.
#
# Why: flutter_secure_storage_linux → libsecret → Secret Service D-Bus API.
# Outside a sandbox this is served by whatever gnome-keyring-daemon PAM
# started at login. In an xrdp/VNC session with an XFCE/Cinnamon host,
# either the daemon isn't running, or the host keyring is still locked
# because PAM couldn't get the login password over RDP — libsecret then
# throws PlatformException(keyring_locked) and the app can't proceed
# past Add Account → Request Access.
#
# Instead of relying on any of that, we ship our own gnome-keyring-daemon
# and let it own `org.freedesktop.secrets` on the sandbox's session bus
# (see finish-args: --own-name). It's fully isolated from the host, so
# host desktop / RDP session state cannot break us.
#
# `--components=secrets` restricts it to Secret Service only (no ssh-agent,
# no pkcs11 store). `--unlock` reads the master password from stdin so the
# keyring is immediately usable; the empty password here is fine because
# the sandbox's XDG_DATA_HOME (`~/.var/app/<app-id>/data/keyrings/`) is
# already per-app-isolated by Flatpak — the app-installation boundary IS
# the security perimeter here, not a keyring password.
set -e

if command -v gnome-keyring-daemon >/dev/null 2>&1; then
    eval "$(printf '' | gnome-keyring-daemon --daemonize --unlock --components=secrets 2>/dev/null || true)"
    export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
fi

exec /app/bin/icd360s_mail_client "$@"
