#!/usr/bin/env bash

PEEKLEN=256
VERBOSE=true
OPMSGHOME=~/.opmsg
GPGHOME=~/.gnupg
PFCRYPTMODE=${PFCRYPTMODE:-axolotl} # for testing use: shared

SOF=''
DMODE=''
MODE=''
BACKEND=''
INFILE='/dev/stdin'

RECIPIENTS=()
GPGKEYS=()
OPMSGKEYS=()
PITCHFORKKEYS=()

case "$PFCRYPTMODE" in
    shared) PFENCRYPT=encrypt; PFDECRYPT=decrypt;;
    axolotl) PFENCRYPT=send; PFDECRYPT=recv;;
    none) ;;
    *) echo -e "unsupported PITCHFORK crypt mode '$PFCRYPTMODE'.\nabort." >&2; exit 1;;
esac

getmode() {
    while [[ -n "$1" ]]; do
        case "$1" in
            --encrypt) DMODE=MODE_ID; MODE="ENCRYPT"; return;;
            -e) DMODE=MODE_ID; MODE="ENCRYPT"; return;;
            --decrypt) DMODE=MODE_PEEK; MODE="DECRYPT"; return;;
            -d) DMODE=MODE_PEEK; MODE="DECRYPT"; return;;
            --sign) DMODE=MODE_ID; MODE="SIGN"; return;;
            -s) DMODE=MODE_ID; MODE="SIGN"; return;;
            --verify) DMODE=MODE_PEEK; MODE="VERIFY"; return;;
            -v) DMODE=MODE_PEEK; MODE="VERIFY"; return;;
            --list-keys) DMODE=MODE_LIST; MODE="LIST"; return;;
            -k) DMODE=MODE_LIST; MODE="LIST"; return;;
            --list-sig) DMODE=MODE_LIST; MODE="LISTSIGS"; return;;
            --list-secret-keys) DMODE=MODE_LIST; MODE="LISTSECRET"; return;;
            -K) DMODE=MODE_LIST; MODE="LISTSECRET"; return;;
            --export) DMODE=MODE_PORT; MODE="EXPORT"; return;;
            --import) DMODE=MODE_PORT; MODE="IMPORT"; return;;
        esac
        shift
    done
}

checkkey() {
    echo checkkey >&2
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|-u|--recipient|--local-user|--encrypt-to|--hidden-encrypt-to)
                while [[ "$2" != -* ]] && [[ -n "$2" ]]; do
                    RECIPIENTS+=($2)
                    shift
                done
                ;;
            -c|--confdir) OPMSGHOME=$2; shift;;
            --homedir) GPGHOME=$2; shift;;
        esac
        shift
    done
    # check if recipient has key in backends
    for r in "${RECIPIENTS[@]}"; do
        # pitchfork
        [[ "$PFCRYPTMODE" != "none" ]] && pitchfork plist $PFCRYPTMODE |
            fgrep -qs "$r" && {
                PITCHFORKKEYS+=($r)
                continue
            }

        # opmsg
        opmsg -c $OPMSGHOME --listpgp 2>/dev/null |
            tr -d ' ' |
            fgrep -qs "$r" && {
                OPMSGKEYS+=($r)
                continue
            }

        # fallback to gnupg
        gpg --homedir $GPGHOME --fingerprint --with-colons --trust-model always $r >/dev/null 2>&1 && {
            GPGKEYS+=($r)
            continue
        }

        echo -e "no backend found for user: $r\nabort." >&2
        exit 1
    done
    backendsused=0
    [[ ${#PITCHFORKKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="PITCHFORK"
        $VERBOSE && echo "PITCHFORK keys: ${PITCHFORKKEYS[@]}" >&2
    }
    [[ ${#OPMSGKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="OPMSG"
        $VERBOSE && echo "OPMSG keys: ${OPMSGKEYS[@]}" >&2
    }
    [[ ${#GPGKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="GNUPG"
        $VERBOSE && echo "GPG keys: ${GPGKEYS[@]}" >&2
    }
    [[ $backendsused -gt 1 ]] && {
        echo -n "cannot handle mixed backends\nabort." >&2
        exit 1
    }
    [[ $backendsused -eq 0 ]] && {
        echo -n "no backends found for recipients specified\nabort." >&2
        exit 1
    }
}

getinfile() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --encrypt|-e|--decrypt|-d|--sign|-s|--verify|-V) ;;
            --recipient|-r|--output|-o|--local-user|-u) shift ;;
            --status-fd|-f|--encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--confdir|-c|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--armor) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            *) break;;
        esac
        shift
    done
    [[ $# -gt 0 ]] && INFILE="$1"
    $VERBOSE && echo "infile: $INFILE" >&2
}

peek() {
    getinfile "$@"
    SOF=$(head -c $PEEKLEN $INFILE)
    case "$SOF" in
        *-----BEGIN\ PGP\ MESSAGE-----*) BACKEND=GNUPG;;
        *-----BEGIN\ PGP\ SIGNATURE-----*) BACKEND=GNUPG;;
        *-----\ begin\ PITCHFORK\ MSG\ armor\ -----*) BACKEND=PITCHFORK;;
        *-----\ begin\ PITCHFORK\ SIGNATURE\ armor\ -----*) BACKEND=PITCHFORK;;
        *-----BEGIN\ OPMSG-----*) BACKEND=OPMSG;;
    esac
    $VERBOSE && echo "backend: $BACKEND" >&2
}
# $peeked && cat || { echo -n "$SOF"; cat; }

run_opmsg() {
    cmd=()
    output=''
    statusfd=''
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--confdir) OPMSGHOME=$2; shift;;
            -o|--output) output="$2"; shift ;;
            -f|--status-fd) statusfd="$2"; shift;;
            --encrypt|-e|--decrypt|-d|--sign|-s|--verify|-V) ;;
            --recipient|-r|--local-user|-u) shift ;;
            --encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--armor) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            *) break;;
        esac
        shift
    done
    [[ -z "$INFILE" && $# -gt 0 ]] && INFILE="$1"

    [[ -n "$OPMSGHOME" ]] && {
        cmd+=('-c')
        cmd+=($OPMSGHOME)
    }

    [[ -n "$statusfd" && $statusfd -ne 2 ]] && exec $statusfd>&2

    # sigaction(SIGINT, &sa, nullptr);
    # sigaction(SIGPIPE, &sa, nullptr);

    case "$MODE" in
        ENCRYPT)
            [[ ${#OPMSGKEYS[@]} -lt 1 ]] && { echo -n "no recipients specified.\nabort." >&2; exit 1; }
            cmd+=(--encrypt)
            cmd+=(${OPMSGKEYS[@]}) # todo test how to handle multiple recipients
            cmd+=(--in)
            cmd+=($INFILE)
            [[ -n "$output" ]] && {
                cmd+=(--out)
                cmd+=($output)
            }
            ;;
        DECRYPT)
            cmd+=(--decrypt)
            cmd+=(--in)
            cmd+=($INFILE)
            [[ -n "$output" ]] && {
                cmd+=(--out)
                cmd+=($output)
            }
            /usr/bin/opmsg "${cmd[@]}" && {
                [[ "$OPMUX_MUA" != "mutt" ]] && {
                    echo -ne "\n[GNUPG:] SIG_ID KEEPAWAYFROMFIRE 1970-01-01 0000000000" >&2
                    echo -ne "\n[GNUPG:] GOODSIG 7350735073507350 opmsg" >&2
                    echo -ne "\n[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1970-01-01 00000000000" >&2
                    echo -ne " 0 4 0 1 8 01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >&2
                    echo -ne "\n[GNUPG:] TRUST_ULTIMATE\n" >&2
                }
            }
            exit $?
            ;;
        #SIGN) ;;
        #VERIFY) ;;
        LIST)
            cmd+=(--listpgp)
            cmd+=(--short)
            [[ $# -gt 0 ]] && { cmd+=(--name); cmd+=($1); };;  # todo test --list <keyid>
        #LISTSECRET) ;;
        #EXPORT) ;;
        #IMPORT) ;;
        *) echo -e "unsported opmsg mode\nabort." >&2; exit 1;;
    esac
    /usr/bin/opmsg "${cmd[@]}"
}

run_pitchfork() {
    cmd=()
    output='/dev/stdout'
    statusfd=''
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--confdir) OPMSGHOME=$2; shift;;
            -o|--output) output="$2"; shift ;;
            -f|--status-fd) statusfd="$2"; shift;;
            --encrypt|-e|--decrypt|-d|--sign|-s|--verify|-V) ;;
            --recipient|-r|--local-user|-u) shift ;;
            --encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--armor) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            *) break;;
        esac
        shift
    done
    [[ -z "$INFILE" && $# -gt 0 ]] && INFILE="$1"
    [[ -n "$statusfd" && $statusfd -ne 2 ]] && exec $statusfd>&2

    case "$MODE" in
        ENCRYPT)
            [[ ${#PITCHFORKKEYS[@]} -lt 1 ]] && { echo -n "no recipients specified.\nabort." >&2; exit 1; }
            # todo handle multiple recipients
            # convert back keyid to key name
            name=$(pitchfork plist $PFCRYPTMODE | fgrep "uid:u::::1:0:${PITCHFORKKEYS[@]}" | cut -d: -f10)
            armor "PITCHFORK MSG" pitchfork $PFENCRYPT "$name" <$INFILE >$output
            ;;
        DECRYPT)
            dearmor 'PITCHFORK MSG' pitchfork $PFDECRYPT <$INFILE >$output && {
                [[ "$OPMUX_MUA" != "mutt" ]] && {
                    echo -ne "\n[GNUPG:] SIG_ID KEEPAWAYFROMFIRE 1970-01-01 0000000000" >&2
                    echo -ne "\n[GNUPG:] GOODSIG 7350735073507350 opmsg" >&2
                    echo -ne "\n[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1970-01-01 00000000000" >&2
                    echo -ne " 0 4 0 1 8 01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >&2
                    echo -ne "\n[GNUPG:] TRUST_ULTIMATE\n" >&2
                }
            }
            exit $?
            ;;
        #SIGN) ;;
        #VERIFY) ;;
        #LIST)
        #LISTSECRET) ;;
        #EXPORT) ;;
        #IMPORT) ;;
        *) echo -e "unsported pitchfork mode\nabort." >&2; exit 1;;
    esac
}

####### main

getmode "$@"

case "$DMODE" in
    MODE_ID) checkkey "$@";;
    MODE_PEEK) peek "$@";;
    #MODE_LIST) list "$@";;
    #MODE_PORT) port "$@";;
    *) echo "could not determine mode. aborting" >&2; exit 1;;
esac

#{ [[ "$INFILE" == "/dev/stdin" ]] && { echo -n "$SOF"; cat; } } |
case "$BACKEND" in
    GNUPG) /usr/bin/gpg "$@";;
    OPMSG) run_opmsg "$@";;
    PITCHFORK) run_pitchfork "$@";;
    *) echo -e "'$BACKEND' is not a valid backend.\nabort" >&2; exit 1;;
esac
