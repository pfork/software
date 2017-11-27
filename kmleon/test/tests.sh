#!/usr/bin/env bash

dotest() {
    stderr=$(mktemp)
    [[ -z "$stdout" ]] && stdout=$(mktemp)
    [[ -z "$stdin" ]] && stdin="/dev/null"

    echo -n "[$backend/$style] $1 ... "
    ../kmleon.sh $2 2>$stderr >"$stdout" <"$stdin" && {
        echo "ok"
        rm -f $stderr
    } || {
        echo "fail"
        echo $2
        cat $stdout
        cat $stderr
        exit 1
    }
    rm -f $stderr
}

TESTENV="--homedir .pgp --no-default-keyring --secret-keyring .pgp/secring.gpg --keyring .pgp/pubring.gpg"

### enigmail testcases
### taken from stracing an enigmail run

# common enigmail gpg params
enigmail_common="$TESTENV --charset utf-8 --display-charset utf-8 --batch --no-tty"
enigmail_common_agent="$enigmail_common --use-agent --status-fd 2 "

# exception: doesn't use $enigmail_common-agent
enigmail_version() {
    title="get version"
    cmd="--version --version $enigmail_common"
    dotest "$title" "$cmd"
}
enigmail_config() {
    title="get config"
    cmd="$enigmail_common_agent --fixed-list-mode --with-colons --list-config"
    dotest "$title" "$cmd"
}
enigmail_listkeys() {
    title="list keys"
    cmd="$enigmail_common_agent --with-fingerprint --fixed-list-mode --with-colons --list-keys"
    dotest "$title" "$cmd"
}
enigmail_listsecrets() {
    title="list secret keys"
    cmd="$enigmail_common_agent --with-fingerprint --fixed-list-mode --with-colons --list-secret-keys"
    dotest "$title" "$cmd"
}
enigmail_listsigs() { # needs a pub key id
    title="list signatures"
    cmd="$enigmail_common_agent --with-fingerprint --fixed-list-mode --with-colons --list-sig $1"
    dotest "$title" "$cmd"
}
enigmail_export() { # needs a pub key id
    title="export"
    cmd="$enigmail_common_agent -a --export $1"
    dotest "$title" "$cmd"
}
enigmail_encryptsign() { # needs 2 pub key ids and a secret key id
    title="encrypt+sign"
    cmd="$enigmail_common_agent -a -t --encrypt --sign --trust-model always --encrypt-to $1 -r $2 -u $3"
    dotest "$title" "$cmd"
}
enigmail_encrypt1() { # needs 2 pub key ids and a secret key id
    title="encrypt (w owner key)"
    cmd="$enigmail_common_agent -a -t --encrypt --trust-model always --encrypt-to $1 -r $2 -u $3"
    dotest "$title" "$cmd"
}
enigmail_encrypt2() { # needs 2 pub key ids
    title="encrypt (w/o owner key)"
    cmd="$enigmail_common_agent -a -t --encrypt --trust-model always -r $1 -u $2"
    dotest "$title" "$cmd"
}
enigmail_decrypt() {
    title="decrypt"
    cmd="$enigmail_common_agent --max-output 418600 --decrypt" # max-output is against zipbombs
    dotest "$title" "$cmd"
}

### mutt test-cases, taken from
### https://dev.mutt.org/trac/wiki/MuttGuide/UseGPG#TheCodeSourcerymethodofMuttsetupandexplanation
mutt_common="$TESTENV --no-verbose"
mutt_common_batch="$mutt_common --batch --output -"

mutt_verify() { # needs file with a signature and a signed file
    title="verify"
    cmd="$mutt_common_batch --verify $1 $2"
    dotest "$title" "$cmd"
}
mutt_decrypt() { # needs a file to decrypt
    title="decrypt"
    cmd="$mutt_common_batch --passphrase-fd 0 $1"
    dotest "$title" "$cmd"
}
mutt_sign_with_user() { # needs a signer key id and a file to sign
    title="sign (with user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --armor --detach-sign --textmode -u $1 $2"
    dotest "$title" "$cmd"
}
mutt_sign_without_user() { # needs a file to sign
    title="sign (without user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --armor --detach-sign --textmode $1"
    dotest "$title" "$cmd"
}
# clearsign is "strongly deprecated" according to mutt documentation
mutt_clearsign_with_user() { # needs a signer key id and a file to sign
    title="clearsign (with user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --armor --textmode --clearsign -u $1 $2"
    dotest "$title" "$cmd"
}
mutt_clearsign_without_user() { # needs a file to sign
    title="clearsign (without user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --armor --textmode --clearsign $1"
   dotest "$title" "$cmd"
}
mutt_encrypt() { # needs 3 users to encrypt to and a file to encrypt
    title="encrypt"
    cmd="$mutt_common_batch --quiet --encrypt --textmode --armor --always-trust --encrypt-to $1 -r $2 -r $3 -- $4"
    dotest "$title" "$cmd"
}
mutt_encrypt_sign_with_user() { # needs a signer key id, 3 users to encrypt to and a file to encrypt and sign
    title="encrypt+sign (with user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --quiet --textmode --encrypt --sign -u $1 --armor --always-trust --encrypt-to $2 -r $3 -r $4 -- $5"
    dotest "$title" "$cmd"
}
mutt_encrypt_sign_without_user() { # needs 3 users to encrypt to and a file to encrypt and sign
    title="encrypt+sign (without user)"
    cmd="$mutt_common_batch --passphrase-fd 0 --quiet --textmode --encrypt --sign --armor --always-trust --encrypt-to $1 -r $2 -r $3 -- $4"
    dotest "$title" "$cmd"
}
mutt_export() { # needs a key id
    title="export key"
    cmd="$mutt_common --export --armor $1"
    dotest "$title" "$cmd"
}
mutt_import() { # needs a key in a file to import
    title="import key"
    cmd="$mutt_common --import -v $1"
    dotest "$title" "$cmd"
}
mutt_verify_key() { # needs a key id
    title="verify key"
    cmd="$mutt_common --batch --fingerprint --check-sigs $1"
    dotest "$title" "$cmd"
}
mutt_list_pubring() { # needs a key id
    title="list keys"
    cmd="$mutt_common --batch --with-colons --list-keys $1"
    dotest "$title" "$cmd"
}
mutt_list_secring() { # needs a key id
    title="list secret keys"
    cmd="$mutt_common --batch --with-colons --list-secret-keys $1"
    dotest "$title" "$cmd"
}

test_enigmail() {
    style="enigmail"
    enigmail_version
    enigmail_config
    enigmail_listkeys
    enigmail_listsecrets
    enigmail_listsigs $pk
    stdout="$exported" enigmail_export $pk
    # todo enigmail_import
    stdin="$msg" stdout="$ciphertext" enigmail_encryptsign $pk $pk1 $sk
    stdin="$ciphertext" enigmail_decrypt
    stdin="$msg" stdout="$ciphertext" enigmail_encrypt1 $pk $pk1 $sk
    stdin="$ciphertext" enigmail_decrypt
    stdin="$msg" stdout="$ciphertext" enigmail_encrypt2 $pk $pk1
    stdin="$ciphertext" enigmail_decrypt
}

test_mutt() {
    style="mutt"
    stdout="$sig" mutt_sign_with_user $sk "$msg"
    mutt_verify "$sig" "$msg"
    DEFAULTBACKEND=${backend^^} DEFAULTKEY=$sk stdout="$sig" mutt_sign_without_user "$msg"
    mutt_verify "$sig" "$msg"
    [[ "$backend" == "gnupg" ]] && { # ops only supported with gnupg backend
        stdout="$sig" mutt_clearsign_with_user $sk "$msg"
        mutt_verify "$sig"
        DEFAULTBACKEND=${backend^^} DEFAULTKEY=$sk stdout="$sig" mutt_clearsign_without_user "$msg"
        mutt_verify "$sig"
        mutt_verify_key $pk
    }
    stdout="$ciphertext" mutt_encrypt $pk $pk1 $pk2 "$msg"
    mutt_decrypt "$ciphertext"
    stdout="$ciphertext" mutt_encrypt_sign_with_user $sk $pk $pk1 $pk2 "$msg"
    stdout="$ciphertext" mutt_encrypt_sign_without_user $pk $pk1 $pk2 "$msg"
    stdout="$exported" mutt_export $pk
    OPMSGHOME=.opmsg2 GPGHOME=.pgp2 mutt_import "$exported"
    mutt_list_pubring $pk
    mutt_list_secring $sk
}

msg=$(mktemp)
echo "test message" >$msg
ciphertext=$(mktemp)
exported=$(mktemp)
sig=$(mktemp)

#### test with gnupg ####

backend="gnupg"

# create some PGP users
rm -rf .pgp
pk=$(./newpgp alice alice@example.com)
pk1=$(./newpgp bob bob@example.com)
pk2=$(./newpgp charlie charlie@example.com)
sk=$pk2

mkdir -p .pgp2

test_enigmail
test_mutt

#### test with opmsg ####

backend="opmsg"

# create some opmsg users
rm -rf .opmsg
pk=$(./newopmsg alice alice@example.com)
pk1=$(./newopmsg bob bob@example.com)
pk2=$(./newopmsg charlie charlie@example.com)
sk=$pk2

cat >.opmsg/config <<EOF
version=2
my_id = $sk
rsa_len = 4096
dh_plen = 2048
calgo = aes128ctr
idformat = split
new_dh_keys = 3
curve = brainpoolP320r1
peer_isolation=1
EOF

mkdir -p .opmsg2
cp -f .opmsg/config .opmsg2

OPMSGHOME=.opmsg test_enigmail
OPMSGHOME=.opmsg test_mutt

#pfranz=$(pitchfork plist shared | fgrep uid:u::: | cut -d: -f8)
#longterm=$(pitchfork plist longterm | fgrep uid:u::: | cut -d: -f8)

