#!/usr/bin/env bash

# simple caching wrapper around `pitchfork list`

PITCHFORKHOME=~/.pitchfork
CACHETIME="2 minutes ago"

self=$0

usage() {
    echo -e "usage: $0 plist <axolotl|sphincs|shared|longterm|prekey|pub>\nabort." >&2
    exit 1
}

plist() {
    [[ $# -eq 2 ]] || {
        echo "cannot handle user in list commands" >&2
        usage "$@"
    }

    case "$2" in
        axolotl|sphincs|shared|longterm|prekey|pub) ;;
        *)
            echo "error bad type: $2" >&2
            usage "$@"
            ;;
    esac

    [[ -d "$PITCHFORKHOME" ]] || mkdir -p "$PITCHFORKHOME"

    [[ -f "$PITCHFORKHOME/$2.keys" ]] && {
        [[ $(stat -c %Y "$PITCHFORKHOME/$2.keys") -gt $(date -d "$CACHETIME" +%s) ]] && {
            touch "$PITCHFORKHOME/$2.keys"
            exec cat "$PITCHFORKHOME/$2.keys"
        }
    }

    if pitchfork "$1" "$2" >"$PITCHFORKHOME/$2.keys"; then
       cat "$PITCHFORKHOME/$2.keys" 
    else
       rm "$PITCHFORKHOME/$2.keys"
    fi
}

multi_encrypt() {
    # convert back keyid to key name
    op=$1
    shift

    name=$($self plist "$PFKEYTYPE" | grep -F "uid:u::::1:0:$*" | cut -d: -f10)
    [[ -z "$name" ]] && exit 1
    armor "PITCHFORK MSG" pitchfork "$op" "$name"
}

multi_decrypt() {
    pitchfork "${@}"
}

case "$1" in
    plist) plist "$@" ;;
    encrypt|ancrypt|send) multi_encrypt "$@" ;;
    decrypt|andecrypt|recv) multi_decrypt "$@" ;;
    *) pitchfork "$@";;
esac
