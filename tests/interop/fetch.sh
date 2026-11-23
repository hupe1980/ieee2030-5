#!/bin/sh
# 008-interop/SR-001. Fetch peer sources into a new or matching existing directory.
set -eu
destination=${1:?usage: fetch.sh DESTINATION}
mkdir -p "$destination"
while read -r url revision; do
    case "$revision" in *[!a-f0-9]*|'') exit 1 ;; esac
    test "${#revision}" = 40
    directory=$destination/${url##*/}
    if [ ! -d "$directory/.git" ]; then
        git init -q "$directory"
        git -C "$directory" fetch --quiet --depth=1 "$url" "$revision"
        git -C "$directory" checkout --quiet --detach FETCH_HEAD
    fi
    test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
    test -z "$(git -C "$directory" status --porcelain --ignored=matching)"
done < "$(dirname "$0")/peers.lock"
