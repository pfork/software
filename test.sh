#!/bin/ash

echo "testing getpub"
./pitchfork getpub >pubkey

echo "testing entropy"
./pitchfork rng 1023 >/tmp/entropy
ls -l /tmp/entropy; ent /tmp/entropy

echo "testing pq-x3dh, start"
echo "put in Alice pitchfork, press enter"; read
./pitchfork kex >/tmp/kex
echo "testing pq-x3dh, respond"
echo "put in Bob pitchfork, press enter"; read
./pitchfork respond Alice </tmp/kex >/tmp/response
echo "testing pq-x3dh, finish"
echo "put in Alice pitchfork, press enter"; read
./pitchfork end Bob </tmp/response

echo "testing xeddsa signing"
echo "sign me" | ./pitchfork sign >/tmp/signature
echo "testing xeddsa signature verification"
{cat /tmp/signature; echo "sign me" } | ./pitchfork verify Bob
echo "testing xeddsa signature verification failing"
{cat /tmp/signature; echo "sign it" } | ./pitchfork verify Bob

echo "testing shared key encryption"
echo 'PITCHFORK!!5!' | ./pitchfork encrypt Bob >/tmp/cipher
echo "testing shared key decryption"
./pitchfork decrypt Bob </tmp/cipher

echo "testing anonymous encryption"
{cat pubkey ; echo "hello stranger" } | ./pitchfork ancrypt >/tmp/ancrypted
echo "testing anonymous decryption"
./pitchfork andecrypt </tmp/ancrypted

echo "testing axolotl protocol"
echo '1<3u' | ./pitchfork send Bob >/tmp/ciphertext
echo "put in Bob pitchfork, press enter"; read
./pitchfork recv Alice </tmp/ciphertext
