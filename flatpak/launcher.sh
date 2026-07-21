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
    echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unset}"
    echo "daemon binary: $(command -v gnome-keyring-daemon || echo NOT_FOUND)"

    if ! command -v gnome-keyring-daemon >/dev/null 2>&1; then
        echo "FATAL: gnome-keyring-daemon not on PATH; skipping keyring bootstrap"
    else
        # Per the gnome-keyring-daemon(1) man page, `--login` is PAM-only:
        # it reads the login password from stdin, but "does not complete
        # actual initialization" and prints "only a few environment
        # variables". `GNOME_KEYRING_CONTROL` in particular is NOT among
        # them — v2.155.10 shipped `--login` and the daemon exited 0 with
        # empty stdout, so nothing got exported, so libsecret still
        # couldn't find the Secret Service on the bus.
        #
        # `--unlock` on its own does the full init AND creates the login
        # keyring if it doesn't exist yet ("Read a password from stdin,
        # and use it to unlock the login keyring or create it if the login
        # keyring does not exist"), so it's the right primitive for a
        # non-PAM launcher.
        #
        # `printf '\n'` sends a bare newline, which the daemon reads as an
        # empty password (not EOF — `printf ''` was the earlier bug, EOF
        # aborts unlock with "no password on stdin"). Empty password is
        # fine because the Flatpak per-app data dir is already the
        # security boundary; layering a second password would be UX
        # friction with no threat-model benefit.
        echo "--- launching daemon (--daemonize --unlock --components=secrets) ---"
        DAEMON_OUT=$(printf '\n' | gnome-keyring-daemon --daemonize --unlock --components=secrets 2>&1)
        DAEMON_EXIT=$?
        echo "daemon exit code: $DAEMON_EXIT"
        echo "daemon stdout/stderr:"
        echo "$DAEMON_OUT" | sed 's/^/    /'

        # gnome-keyring prints shell-eval-able env exports (GNOME_KEYRING_CONTROL=..., SSH_AUTH_SOCK=...)
        # ONLY on stdout, and only the lines matching FOO=BAR are safe to eval.
        while IFS= read -r line; do
            case "$line" in
                GNOME_KEYRING_CONTROL=*|SSH_AUTH_SOCK=*)
                    export "${line?}"
                    echo "exported: $line"
                    ;;
            esac
        done <<< "$DAEMON_OUT"

        # Sanity check: is org.freedesktop.secrets now on the session bus?
        # busctl is NOT shipped in org.freedesktop.Platform 24.08, so this
        # will normally print "busctl not on PATH" — that's fine, the
        # exported vars above are the real signal.
        if command -v busctl >/dev/null 2>&1 && [ -n "$DBUS_SESSION_BUS_ADDRESS" ]; then
            echo "--- checking Secret Service on session bus ---"
            busctl --user list 2>&1 | grep -F "org.freedesktop.secrets" | sed 's/^/    /' || echo "    org.freedesktop.secrets NOT on session bus"
        else
            echo "busctl not on PATH; skipping bus sanity check"
        fi
    fi

    echo "=== launcher.sh handing off to Flutter binary ==="
} >> "$KLOG" 2>&1

exec /app/bin/icd360s_mail_client "$@"
