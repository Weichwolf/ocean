#!/bin/sh
set -eu

case "$1" in
    write)
        printf '%s\n' "$2" > /data/checkpoint.next
        mv /data/checkpoint.next /data/checkpoint
        sync -f /data/checkpoint
        ;;
    read)
        test "$(cat /data/checkpoint)" = "$2"
        ;;
    *)
        exit 2
        ;;
esac

exec busybox httpd -f -vv -p 8080 -h /data
