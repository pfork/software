#!/usr/bin/env bash

# todo implement
#  - mixed backend support

# how far to peek into input for deciding the backend
PEEKLEN=256
# we are verbose by default
VERBOSE=${VERBOSE:-true}
# where is the default home for opmsg
OPMSGHOME=${OPMSGHOME:-~/.opmsg}
# where is the default home for gnupg
GPGHOME=${GPGHOME:-~/.gnupg}
# what is the default keytype for the PITCHFORK
PFKEYTYPE=${PFKEYTYPE:-axolotl} # for testing use: shared
PITCHFORK=pitchfork.sh

DEFAULTBACKEND=${DEFAULTBACKEND:-OPMSG}

# global vars, *not* for configuration!
SOF=''
DMODE=''
MODE=''
BACKEND=''
INFILE='/dev/stdin'

RECIPIENTS=()
GPGKEYS=()
OPMSGKEYS=()
PITCHFORKKEYS=()
GPGSIGKEY=''
OPMSGSIGKEY=''
PITCHFORKSIGKEY=''
PITCHFORKPQSIGKEY=''

# PITCHFORK ops depend on the key type
case "$PFKEYTYPE" in
    shared) PFENCRYPT=encrypt; PFDECRYPT=decrypt;;
    axolotl) PFENCRYPT=send; PFDECRYPT=recv;;
    none) ;;
    *) echo -e "unsupported PITCHFORK crypt mode '$PFKEYTYPE'.\nabort." >&2; exit 1;;
esac

# figure out if we are encrypting, decrypting, signing, verifying or doing something else
getmode() {
    while [[ -n "$1" ]]; do
        case "$1" in
            --encrypt) DMODE=MODE_ID; MODE="ENCRYPT"; return;;
            -e) DMODE=MODE_ID; MODE="ENCRYPT"; return;;
            --decrypt) DMODE=MODE_PEEK; MODE="DECRYPT"; return;;
            -d) DMODE=MODE_PEEK; MODE="DECRYPT"; return;;
            --sign) DMODE=MODE_ID; MODE="SIGN"; return;;
            -s) DMODE=MODE_ID; MODE="SIGN"; return;;
            --detach-sign) DMODE=MODE_ID; MODE="SIGN"; return;;
            --clearsign) DMODE=MODE_ID; MODE="SIGN"; return;;
            --clear-sign) DMODE=MODE_ID; MODE="SIGN"; return;;
            --verify) DMODE=MODE_PEEK; MODE="VERIFY"; return;;
            -v) DMODE=MODE_PEEK; MODE="VERIFY"; return;;
            --list-keys) DMODE=MODE_LIST; MODE="LIST"; return;;
            -k) DMODE=MODE_LIST; MODE="LIST"; return;;
            --list-sig) DMODE=MODE_LIST; MODE="LISTSIGS"; return;;
            --list-secret-keys) DMODE=MODE_LIST; MODE="LISTSECRET"; return;;
            -K) DMODE=MODE_LIST; MODE="LISTSECRET"; return;;
            --export) DMODE=MODE_PORT; MODE="EXPORT"; return;;
            --import) DMODE=MODE_PORT; MODE="IMPORT"; return;;
            --check-sigs|--version|--list-config) DMODE=gpg_op; return
        esac
        shift
    done
    # default is to decrypt
    DMODE=MODE_PEEK; MODE="DECRYPT";
}

checkkey() {
    #echo checkkey >&2
    SIGNER=''
    # figure out peers we need keymaterial for
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--default-key|--local-user)
                [[ -n "$SIGNER" ]] && {
                    # soft fail
                    echo "Warning over-riding already set signer: '$SIGNER' with '$2'" >&2
                    # hard fail?
                    #echo -e "Over-riding already set signer: '$SIGNER' with '$2'\nabort." >&2
                    #exit 1
                }
                SIGNER="$2"
                shift
                ;;
            -r|--recipient|--encrypt-to|--hidden-encrypt-to)
                RECIPIENTS+=($2)
                shift
                ;;
            --homedir) GPGHOME=$2; shift;;
        esac
        shift
    done

    [[ "$MODE" == "SIGN" ]] && PFKEYTYPE=longterm ||
            [[ "$MODE" == "VERIFY" ]] && PFKEYTYPE=longterm

    # check if recipient has key in backends
    for r in "${RECIPIENTS[@]}"; do
        # pitchfork
        [[ "$PFKEYTYPE" != "none" ]] && $PITCHFORK plist $PFKEYTYPE 2>/dev/null |
            fgrep -qs "$r" && {
                PITCHFORKKEYS+=($r)
                continue
            }

        # opmsg
        opmsg -c $OPMSGHOME --listpgp --long 2>/dev/null |
            fgrep -qs "$r" && {
                OPMSGKEYS+=($r)
                continue
            }

        # fallback to gnupg
        gpg --homedir $GPGHOME --fingerprint --with-colons --trust-model always $r >/dev/null 2>&1 && {
            GPGKEYS+=($r)
            continue
        }

        [[ "$MODE" == "EXPORT" ]] && return

        echo -e "no backend found for user: $r\nabort." >&2
        exit 1
    done

    # check backend for signing key
    [[ -n "$SIGNER" ]] && {
        # pitchfork
        $PITCHFORK plist longterm 2>/dev/null |
            fgrep -qs "$SIGNER" && {
                PITCHFORKSIGKEY=$SIGNER
            } || {

        $PITCHFORK plist sphincs 2>/dev/null |
            fgrep -qs "$SIGNER" && {
                PITCHFORKPQSIGKEY=$SIGNER
            } || {

        # opmsg
        opmsg -c $OPMSGHOME --listpgp --long 2>/dev/null |
            fgrep -qs "$SIGNER" && {
                OPMSGSIGKEY=$SIGNER
            } || {

        # fallback to gnupg
        gpg --homedir $GPGHOME --fingerprint --with-colons --trust-model always $SIGNER >/dev/null 2>&1 && {
            GPGSIGKEY=$SIGNER
        } } } }
    }

    backendsused=0
    [[ ${#PITCHFORKKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="PITCHFORK"
        $VERBOSE && echo "PITCHFORK keys: ${PITCHFORKKEYS[@]}" >&2
    }
    [[ -n "$PITCHFORKSIGKEY" && "$BACKEND" != "PITCHFORK" ]] && {
        BACKEND=PITCHFORK
        backendsused=$((backendsused+1))
    }
    [[ -n "$PITCHFORKPQSIGKEY" && "$BACKEND" != "PITCHFORK" ]] && {
        BACKEND=PITCHFORK
        backendsused=$((backendsused+1))
    }
    [[ ${#OPMSGKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="OPMSG"
        $VERBOSE && echo "OPMSG keys: ${OPMSGKEYS[@]}" >&2
    }
    [[ -n "$OPMSGSIGKEY" && "$BACKEND" != "OPMSG" ]] && {
        BACKEND=OPMSG
        backendsused=$((backendsused+1))
    }
    [[ ${#GPGKEYS[@]} -gt 0 ]] && {
        backendsused=$((backendsused+1))
        BACKEND="GNUPG"
        $VERBOSE && echo "GPG keys: ${GPGKEYS[@]}" >&2
    }
    [[ -n "$GPGSIGKEY" && "$BACKEND" != "GNUPG" ]] && {
        BACKEND=GNUPG
        backendsused=$((backendsused+1))
    }
    [[ $backendsused -gt 1 ]] && { # todo handle mixed backends
        echo -e "cannot handle mixed backends\nabort." >&2
        exit 1
    }
    [[ $backendsused -eq 0 ]] && {
        [[ -z "$DEFAULTBACKEND"  ]] && {
            [[ "$MODE" != "EXPORT" ]] && {
                echo -e "no backends found for recipients specified\nabort." >&2
                exit 1
            }
            return
        }
        BACKEND="$DEFAULTBACKEND"
        case "$BACKEND" in
            OPMSG) OPMSGKEYS+=($DEFAULTKEY);;
            GNUPG) GNUPGKEYS+=($DEFAULTKEY);;
            PITCHFORK) PITCHFORKKEYS+=($DEFAULTKEY);;
            all) ;;
            *)
                echo -e "bad default backend '$DEFAULTBACKEND'.\nabort.";
                exit 1
                ;;
        esac
    }
}

getinfile() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --encrypt|-e|--decrypt|-d|--sign|-s|--verify|-V|--detach-sign) ;;
            --clearsign|--clear-sign|--fingerprint) ;;
            --recipient|-r|--output|-o|--local-user|-u) shift ;;
            --status-fd|-f|--encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--always-trust|--armor|--quiet) ;;
            --export|--import) ;;
            --check-sigs|--version|--list-config) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            --no-verbose) ;;
            --) shift; break;;
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
        *-----BEGIN\ PGP\ PUBLIC\ KEY\ BLOCK-----*) BACKEND=GNUPG;;
        *-----\ begin\ PITCHFORK\ MSG\ armor\ -----*) BACKEND=PITCHFORK;;
        *-----\ begin\ PITCHFORK\ SIGNATURE\ armor\ -----*) BACKEND=PITCHFORK;;
        *-----BEGIN\ OPMSG-----*) BACKEND=OPMSG;;
        *-----BEGIN\ PUBLIC\ KEY-----*) BACKEND=OPMSG;;
    esac
    $VERBOSE && echo "backend: $BACKEND" >&2
}

list() {
    DEFAULTBACKEND=all checkkey "$@"
    [[ "$BACKEND" == "all" ]] && {
        case $MODE in
            LIST)
                gpg --homedir $GPGHOME --quiet --batch --no-verbose --with-colons --trust-model always --list-keys 2>/dev/null
                opmsg -c $OPMSGHOME --listpgp 2>/dev/null
                $PITCHFORK plist $PFKEYTYPE
                exit 0
                ;;
            LISTSECRET)
                # todo add all secret opmsg keys opmsg -c $OPMSGHOME --list 2>/dev/null
                gpg --homedir $GPGHOME --quiet --batch --no-verbose --with-colons --trust-model always --list-secret-keys 2>/dev/null
                $PITCHFORK plist longterm
                $PITCHFORK plist sphincs
                exit 0
                ;;
            LISTSIGS) # neither opmsg nor pitchfork support signed keys
                gpg --homedir $GPGHOME --quiet --batch --no-verbose --with-colons --trust-model always --list-sig 2>/dev/null
                exit 0
                ;;
            *) echo "what is this (list) mode: $MODE"; exit 1;;
        esac
    }
}

run_opmsg() {
    cmd=()
    output=''
    statusfd=''
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output) output="$2"; shift ;;
            -f|--status-fd) statusfd="$2"; shift;;
            --encrypt|-e|--decrypt|-d|--sign|-s|--detach-sign|--fingerprint) ;;
            --clearsign|--clear-sign) echo -e "clearsigning with opmux backend is not supported.\nabort."; exit 1;;
            --verify|-V) ;;
            --recipient|-r|--local-user|-u) shift ;;
            --encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--always-trust|--armor|--quiet) ;;
            --export|--import) ;;
            --check-sigs|--version|--list-config) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            --no-verbose) ;;
            --) shift; break;;
            *) break;;
        esac
        shift
    done

    if [[ "VERIFY" == "$MODE" ]]; then
        if [[ $# -eq 2 ]]; then
            sig="$2"
            INFILE="$1"
        else
            echo -e "non-detached signatures unsupported for opmsg backend.\nabort" &>2
            echo -e "params: $@" &>2
            exit 1
        fi
    else
        [[ $# -gt 0 ]] && INFILE="$1"
    fi

    [[ -n "$OPMSGHOME" ]] && {
        cmd+=('-c')
        cmd+=($OPMSGHOME)
    }

    [[ -n "$statusfd" && $statusfd -ne 2 ]] && exec $statusfd>&2

    # sigaction(SIGINT, &sa, nullptr);
    # sigaction(SIGPIPE, &sa, nullptr);

    case "$MODE" in
        ENCRYPT)
            [[ ${#OPMSGKEYS[@]} -lt 1 ]] && { echo -e "no recipients specified.\nabort." >&2; exit 1; }
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
        SIGN)
            cmd+=(--sign)
            cmd+=(--in)
            cmd+=($INFILE)
            [[ -n "$output" ]] && {
                cmd+=(--out)
                cmd+=($output)
            }
            ;;
        VERIFY)
            cmd+=(--verify)
            cmd+=($sig)
            cmd+=(--in)
            cmd+=($INFILE)
            [[ -n "$output" ]] && {
                cmd+=(--out)
                cmd+=($output)
            }
            ;;
        LIST)
            cmd+=(--listpgp)
            cmd+=(--long)
            [[ $# -gt 0 ]] && { cmd+=(--name); cmd+=($1); };;  # todo test --list <keyid>
        #todo LISTSECRET) ;;
        EXPORT)
            output=${output:-/dev/stdout}
            cat "$OPMSGHOME/$INFILE/"*.pub.pem >$output || exit 1
            exit 0
            ;;
        IMPORT)
            cmd+=(--import)
            cmd+=(--in)
            cmd+=($INFILE)
            ;;
        *) echo -e "unsupported opmsg mode: '$MODE'\nabort." >&2; exit 1;;
    esac
    /usr/bin/opmsg "${cmd[@]}"
}

run_pitchfork() {
    cmd=()
    output='/dev/stdout'
    statusfd=''
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output) output="$2"; shift ;;
            -f|--status-fd) statusfd="$2"; shift;;
            --encrypt|-e|--decrypt|-d|--sign|-s|--verify|-V|--detach-sign|--fingerprint) ;;
            --clearsign|--clear-sign) ;;
            --recipient|-r|--local-user|-u) shift ;;
            --encrypt-to|-r| --passphrase-fd) shift ;;
            --hidden-encrypt-to|--default-key) shift ;;
            --charset|--display-charset) shift ;;
            --compress-algo|--cipher-algo) shift ;;
            --max-output|--digest-algo) shift ;;
            --trust-model|--homedir) shift;;
            --secret-keyring|--keyring) shift;;
            --use-agent|--batch|--no-tty|--always-trust|--armor|--quiet) ;;
            --export|--import) ;;
            --check-sigs|--version|--list-config) ;;
            --textmode|-v|-l|-a|-t|--no-default-keyring) ;;
            --no-verbose) ;;
            --) shift; break;;
            *) break;;
        esac
        shift
    done
    [[ -z "$INFILE" && $# -gt 0 ]] && INFILE="$1"
    [[ -n "$statusfd" && $statusfd -ne 2 ]] && exec $statusfd>&2

    case "$MODE" in
        ENCRYPT)
            [[ ${#PITCHFORKKEYS[@]} -lt 1 ]] && { echo -e "no recipients specified.\nabort." >&2; exit 1; }
            # todo handle multiple recipients
            # todo use only keyids instead of names to select keys.
            armor "PITCHFORK MSG" $PITCHFORK $PFENCRYPT "${PITCHFORKKEYS[@]}" <$INFILE >$output
            ;;
        DECRYPT)
            dearmor 'PITCHFORK MSG' $PITCHFORK $PFDECRYPT <$INFILE >$output && {
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
        SIGN)
            # todo sign should output armor(sig||msg)
            armor "PITCHFORK SIGNATURE" $PITCHFORK sign <$INFILE >$output ;;
        VERIFY)
            # todo verify should try to figure out a keyname instead of stf
            dearmor 'PITCHFORK SIGNATURE' $PITCHFORK verify stf <$INFILE && {
                [[ "$OPMUX_MUA" != "mutt" ]] && {
                    echo -ne "\n[GNUPG:] SIG_ID KEEPAWAYFROMFIRE 1970-01-01 0000000000" >&2
                    echo -ne "\n[GNUPG:] GOODSIG 7350735073507350 opmsg" >&2
                    echo -ne "\n[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1970-01-01 00000000000" >&2
                    echo -ne " 0 4 0 1 8 01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >&2
                    echo -ne "\n[GNUPG:] TRUST_ULTIMATE\n" >&2
                }
            }
            ;;
        #LIST)
        #LISTSECRET) ;;
        EXPORT)
            output=${output:-/dev/stdout}
            case "$PFKEYTYPE" in
                longterm) armor "PITCHFORK 25519 KEY" $PITCHFORK getpub >$output || exit 1 ;;
                sphincs) armor "PITCHFORK SPHINCS KEY" $PITCHFORK getpub sphincs >>$output || exit 1 ;;
                *) echo -e "can only export longterm or sphincs keys, not '$PFKEYTYPE'\nabort." >&2; exit 1 ;;
            esac
            exit 0
            ;;
        #IMPORT) ;;
        *) echo -e "unsported pitchfork mode\nabort." >&2; exit 1;;
    esac
}

####### main

getmode "$@"

# figure out backend
case "$DMODE" in
    MODE_ID) checkkey "$@";;
    MODE_PEEK) peek "$@";;
    MODE_LIST) list "$@";;
    MODE_PORT)
        if [[ "$MODE" == "EXPORT" ]]; then
            getinfile "$@"
            DEFAULTBACKEND='' PFKEYTYPE=longterm checkkey -r $INFILE "$@"
            if [[ -z "$BACKEND" ]]; then
                DEFAULTBACKEND='' PFKEYTYPE=sphincs checkkey -r $INFILE "$@"
                [[ -z "$BACKEND" ]] && {
                    echo -e "no backends found for recipients specified\nabort." >&2
                    exit 1
                }
                PFKEYTYPE=sphincs
            else
                PFKEYTYPE=longterm
            fi
        else
            peek "$@"
        fi
        ;;
    *) /usr/bin/gpg "$@"; exit $? ;; # fall back to gpg handling whatever is asked for
esac

#{ [[ "$INFILE" == "/dev/stdin" ]] && { echo -n "$SOF"; cat; } } |
case "$BACKEND" in
    PITCHFORK) run_pitchfork "$@";;
    OPMSG) run_opmsg "$@";;
    GNUPG) /usr/bin/gpg "$@";;
    *) echo -e "'$BACKEND' is not a valid backend.\nabort" >&2; exit 1;;
esac
