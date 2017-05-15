#!/bin/bash

set -e

echo "testing getpub"
./pitchfork getpub >/tmp/pubkey
echo

echo "testing entropy"
./pitchfork rng 1023 >/tmp/entropy
ls -l /tmp/entropy; ent /tmp/entropy

echo -e "\ntesting pq-x3dh, start"
echo "put in Alice pitchfork, press enter"; read
./pitchfork kex >/tmp/kex
echo -e "\ntesting pq-x3dh, respond"
echo "put in Bob pitchfork, press enter"; read
./pitchfork respond Alice </tmp/kex >/tmp/response
echo -e "\ntesting pq-x3dh, finish"
echo "put in Alice pitchfork, press enter"; read
./pitchfork end Bob </tmp/response

echo -e "\ntesting xeddsa signing"
echo "sign me" | ./pitchfork sign >/tmp/signature
echo -e "\ntesting xeddsa signature verification"
{ cat /tmp/signature; echo "sign me" ; } | ./pitchfork verify Bob
echo -e "\ntesting xeddsa signature verification failing"
{ cat /tmp/signature; echo "sign it" ; } | ./pitchfork verify Bob || true

echo -e "\ntesting shared key encryption"
echo 'PITCHFORK!!5!' | ./pitchfork encrypt Bob >/tmp/cipher
echo -e "\ntesting shared key decryption"
./pitchfork decrypt </tmp/cipher

echo -e "\ntesting anonymous encryption"
{ cat /tmp/pubkey ; echo "hello stranger" ; } | ./pitchfork ancrypt >/tmp/ancrypted
echo -e "\ntesting anonymous decryption"
./pitchfork andecrypt </tmp/ancrypted

echo -e "\ntesting axolotl protocol"
echo '1<3u' | ./pitchfork send Bob >/tmp/ciphertext
echo "put in Bob pitchfork, press enter"; read
./pitchfork recv Alice </tmp/ciphertext

echo -e "\ntesting sphincs pq sigs"
echo "testing sphincs signing"
echo "sign me" | ./pitchfork pqsign >/tmp/pqsign
echo -e "\ntesting getting sphincs pubkey"
./pitchfork getpub sphincs >/tmp/pqpub
echo -e "\ntesting verifying sphincs signature"
{ cat /tmp/pqpub; cat /tmp/pqsign; echo "sign me" ; } | ./pitchfork pqverify
echo -e "\ntesting verifying sphincs signature failing"
{ cat /tmp/pqpub; cat /tmp/pqsign; echo "sign it" ; } | ./pitchfork pqverify || true

echo -e "\ntesting (de)armoring"
./armor msg /bin/dd if=/dev/zero count=1 2>/dev/null | ./dearmor msg hexdump
