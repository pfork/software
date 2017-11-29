#!/usr/bin/env bash

# simple caching wrapper around `pitchfork list`

PITCHFORKHOME=~/.pitchfork
CACHETIME="2 minutes ago"

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
            touch exec cat "$PITCHFORKHOME/$2.keys"
            exec cat "$PITCHFORKHOME/$2.keys"
        }
    }

    pitchfork $1 $2 >"$PITCHFORKHOME/$2.keys" && cat "$PITCHFORKHOME/$2.keys"
}

# only handle plist command
case "$1" in
    plist) plist "$@" ;;
    encrypt|decrypt|ancrypt|andecrypt|send|recv) ;;
    *) exec pitchfork "$@";;
esac
