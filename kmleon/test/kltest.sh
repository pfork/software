#!/bin/sh -e

# create some PGP users
rm -rf .pgp
paula=$(./newpgp paula paula@example.com)
peter=$(./newpgp peter peter@example.com)

# create some opmsg users
rm -rf .opmsg
olivia=$(./newopmsg olivia olivia@example.com)
oscar=$(./newopmsg oscar oscar@example.com)
myself=$(./newopmsg test test@example.com)

pfranz=$(pitchfork plist shared | fgrep uid:u::: | cut -d: -f8)
longterm=$(pitchfork plist longterm | fgrep uid:u::: | cut -d: -f8)

cat >.opmsg/config <<EOF
version=2
my_id = $myself
rsa_len = 4096
dh_plen = 2048
calgo = aes128ctr
idformat = split
new_dh_keys = 3
curve = brainpoolP320r1
peer_isolation=1
EOF

gpgopts="--homedir .pgp --no-default-keyring --secret-keyring .pgp/secring.gpg --keyring .pgp/pubring.gpg --charset utf-8 --display-charset utf-8 --status-fd 2 -a -t --trust-model always"
opmsgopts="--confdir .opmsg"

# encrypt
# gnupg
echo ">gpg encrypt"
echo "asdf" | PFCRYPTMODE=none ../kmleon.sh $gpgopts -a -t --encrypt --encrypt-to $paula -r $peter -u $paula >/tmp/kge

echo -e "\n>gnupg decrypt"
PFCRYPTMODE=none ../kmleon.sh $gpgopts --decrypt /tmp/kge

# sign
# gnupg sign
echo -e "\n>gnupg sign"
echo "asdf" | PFCRYPTMODE=none ../kmleon.sh $gpgopts --sign -u $paula >/tmp/kgs
# todo pitchfork + opmsg

# verify
# gnupg
echo -e "\n>gnupg verify"
PFCRYPTMODE=none ../kmleon.sh $gpgopts -u $peter --verify /tmp/kgs

# opmsg encrypt
echo -e "\n>opmsg encrypt"
echo "asdf" | PFCRYPTMODE=none ../kmleon.sh $opmsgopts $gpgopts --encrypt --encrypt-to $olivia -r $oscar -u $oscar >/tmp/koe

echo -e "\n>opmsg decrypt"
PFCRYPTMODE=none ../kmleon.sh $opmsgopts $gpgopts --decrypt /tmp/koe

# pitchfork
echo -e "\n>pitchfork encrypt"
set -x
echo "asdf" | PFCRYPTMODE=shared ../kmleon.sh $gpgopts --encrypt --encrypt-to $pfranz >/tmp/kpe
echo -e "\n>pitchfork decrypt"
echo "asdf" | PFCRYPTMODE=shared ../kmleon.sh $gpgopts --decrypt </tmp/kpe

# sign
set -x
echo -e "\n>pitchfork sign"
echo "asdf" | ../kmleon.sh $gpgopts --sign -u $longterm >/tmp/kps

# verify
echo -e "\n>pitchfork verify"
../kmleon.sh $gpgopts -u $longterm --verify /tmp/kps
exit 0

# todo opmsg sign/verify

# mixed
echo -e "\n>mixed encrypt"
echo "asdf" | PFCRYPTMODE=none ../kmleon.sh $gpgopts --encrypt -r $oscar -u $paula >/tmp/kme

# todo sign opmsg
# todo sign pitchfork

# wrong mode
echo -e "\n>mode error"
PFCRYPTMODE=none ../kmleon.sh $gpgopts --encrypt --encrypt-to D736BECE10A95FBC -r 0x970DEB6694D50988 -u D736BECE10A95FBC --decrypt --encrypt-to D736BECE10A95FBC -r 0x970DEB6694D50988 -u D736BECE10A95FBC --sign --encrypt-to D736BECE10A95FBC -r 0x970DEB6694D50988 -u D736BECE10A95FBC --encrypt-to D736BECE10A95FBC -r 0x970DEB6694D50988 -u D736BECE10A95FBC --verify - /tmp/b
