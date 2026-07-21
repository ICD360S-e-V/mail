#!/bin/bash
# Wrapper that starts gnome-keyring-daemon inside the sandbox before
# handing off to the Flutter binary. See finish-args
# `--own-name=org.freedesktop.secrets` — the sandbox owns the well-known
# name locally, so `flutter_secure_storage_linux` → libsecret finds a
# working Secret Service without touching whatever the host has (or
# doesn't have, in an xrdp/xdg-desktop-portal-xapp session).
#
# NEVER `set -e` here — if the daemon fails to start we still want to
# hand off to the Flutter binary so the app can show its own error UI
# instead of dying invisibly.

KLOG_DIR="${XDG_DATA_HOME:-$HOME/.var/app/de.icd360s.mailclient/data}/icd360s_mail_client"
KLOG="$KLOG_DIR/keyring-launcher.log"
mkdir -p "$KLOG_DIR"

{
    echo "=== $(date -u +%FT%TZ) launcher.sh v3 ==="
    echo "PATH=$PATH"
    echo "HOME=$HOME"
    echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"
    echo "XDG_DATA_HOME=${XDG_DATA_HOME:-unset}"
    echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unset}"
    echo "daemon binary: $(command -v gnome-keyring-daemon || echo NOT_FOUND)"
    echo "keyring dir before start:"
    ls -la "${XDG_DATA_HOME:-$HOME/.local/share}/keyrings/" 2>&1 | sed 's/^/    /'

    if ! command -v gnome-keyring-daemon >/dev/null 2>&1; then
        echo "FATAL: gnome-keyring-daemon not on PATH; skipping keyring bootstrap"
    else
        # v50 empirical behaviour on freedesktop 24.08 runtime (tested
        # locally in the actual bundle): `--daemonize --unlock --components=secrets`
        # with a bare newline on stdin returns exit 0, prints NOTHING on
        # stdout, forks a working daemon that DOES register
        # `org.freedesktop.secrets` on the session bus AND creates a
        # `login` collection AND aliases it as `default`. The empty
        # stdout is expected — v50 no longer emits GNOME_KEYRING_CONTROL
        # to the caller; libsecret finds the daemon via the standard
        # XDG socket path (${XDG_RUNTIME_DIR}/keyring/control) on its
        # own. See gnome-keyring-daemon(1) `--unlock` section for the
        # first-launch create semantics.
        echo "--- launching daemon (--daemonize --unlock --components=secrets) ---"
        DAEMON_OUT=$(printf '\n' | gnome-keyring-daemon --daemonize --unlock --components=secrets 2>&1)
        DAEMON_EXIT=$?
        echo "daemon exit code: $DAEMON_EXIT"
        echo "daemon stdout/stderr:"
        echo "$DAEMON_OUT" | sed 's/^/    /'

        # If v50 DID print anything, export the eval-able bits anyway
        # (harmless if absent).
        while IFS= read -r line; do
            case "$line" in
                GNOME_KEYRING_CONTROL=*|SSH_AUTH_SOCK=*)
                    export "${line?}"
                    echo "exported: $line"
                    ;;
            esac
        done <<< "$DAEMON_OUT"

        echo "keyring dir after start:"
        ls -la "${XDG_DATA_HOME:-$HOME/.local/share}/keyrings/" 2>&1 | sed 's/^/    /'
        echo "control socket:"
        ls -la "${XDG_RUNTIME_DIR}/keyring" 2>&1 | sed 's/^/    /'
        echo "daemon process:"
        pgrep -a gnome-keyring 2>&1 | sed 's/^/    /' || echo "    (no daemon process found)"

        # v2.155.11 diagnostic: replicate EXACTLY what the flutter plugin
        # does via dbus-send, so the log tells us whether the Secret
        # Service path the plugin uses is actually working from THIS
        # sandbox instance's session bus. Plugin's warmupKeyring() calls:
        #   1. secret_service_get_sync(OPEN_SESSION | LOAD_COLLECTIONS)
        #   2. secret_collection_for_alias_sync(service, DEFAULT, ...)
        #   3. secret_collection_get_locked(collection) → if true, prompt-unlock
        # Any of the three failing → plugin throws "KeyringLocked".
        if command -v dbus-send >/dev/null 2>&1; then
            echo "--- dbus probe: is org.freedesktop.secrets on the bus? ---"
            dbus-send --session --print-reply --reply-timeout=2000 \
                --dest=org.freedesktop.secrets \
                /org/freedesktop/secrets \
                org.freedesktop.DBus.Peer.Ping 2>&1 | sed 's/^/    /' | head -3

            echo "--- dbus probe: ReadAlias(default) → which collection path? ---"
            dbus-send --session --print-reply --reply-timeout=2000 \
                --dest=org.freedesktop.secrets \
                /org/freedesktop/secrets \
                org.freedesktop.Secret.Service.ReadAlias \
                string:default 2>&1 | sed 's/^/    /' | head -5

            echo "--- dbus probe: is login collection Locked? ---"
            dbus-send --session --print-reply --reply-timeout=2000 \
                --dest=org.freedesktop.secrets \
                /org/freedesktop/secrets/collection/login \
                org.freedesktop.DBus.Properties.Get \
                string:org.freedesktop.Secret.Collection string:Locked 2>&1 | sed 's/^/    /' | head -3
        else
            echo "dbus-send not on PATH; skipping Secret Service probe"
        fi
    fi

    echo "=== launcher.sh handing off to Flutter binary ==="
} >> "$KLOG" 2>&1

exec /app/bin/icd360s_mail_client "$@"
