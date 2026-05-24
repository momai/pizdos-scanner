#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ] && [ -d /app/results ]; then
    uid="$(stat -c '%u' /app/results)"
    gid="$(stat -c '%g' /app/results)"

    if [ "$uid" != "0" ]; then
        exec setpriv --reuid "$uid" --regid "$gid" --clear-groups pizdos-scanner "$@"
    fi
fi

exec pizdos-scanner "$@"
