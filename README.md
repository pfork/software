# PITCHFORK host tools

The host tools are a suite of programs helping you work with a
PITCHFORK. Currently it consists of the following:

 - `pitchfork`: the binary to talk to your USB connected PITCHFORK
 - `kmleon`: a replacement for GNUPG handling PITCHFORK, [OPMSG](https://github.com/stealth/opmsg) and GNUPG backends
 - `armor/dearmor`: simple wrapper to ascii armor binary data
 - `pitchfork.sh`: a convenience wrapper around `pitchfork` mostly for kmleon
 - `lib/libpitchfork.so`: a library for accessing a PITCHFORK

## pitchfork

`pitchfork` is the tool that speaks with your PITCHFORK and lets you
initiate cryptographic operations with the keys stored on the
PITCHFORK.

This tool is operating in a pipe mode, that is it expects input on its
standard input and it emits everything on the standard output.

### Getting your curve 25519 public key:

`pitchfork getpub >my-pubkey`

This public key can then be used for verifying signatures and send
messages using the *anonymous one-way mode*.

### Getting your SPHINCS public key:

`pitchfork getpub sphincs >my-pqpubkey`

This public key is necessary for anyone who wants to verify your
SPHINCS signatures.

### Getting random bytes

This command provides you with 1 KByte randomness:

`pitchfork rng 1024 >entropy`

You can also generate an infinite stream of random bytes by omitting
the size:

`pitchfork rng >entropy`

You can always press `ctrl-c` to stop it.

### Stoping operations

`pitchfork stop`

Resets the PITCHFORK internal state in case you interrupted an
operation (e.g. generating infinite random bytes)

### Starting a key-exchange

You can initiate a key-exchange with someone who has a PITCHFORK also
over the internet:

`pitchfork kex >kex`

You have to share the output of this with your partner.

### Responding to a  key-exchange

When someone initiates a key-exchange with you, they will send you the
output of the above `kex` command, this you can then use:

`pitchfork respond Alice <kex >response`

Here `Alice` is the name of your partner, it will be used to identify
the key later on (it is important to note that a name can only be
maximum 32 bytes long.) The output of this command needs to be shared
back with your partner, send the response so your peer can finish
their end of the key-exchange.

### Finishing a key-exchange

To finish a key-exchange that you initiated with the `kex` command,
you have to wait for your peer to send their `response` to you, then
you can:

`pitchfork end Bob <response`

Here `Bob` is the name of your partner, it will be used to identify
the key later when you want to use it (again note, the name cannot be
longer than 32 bytes)

### Signing with short signatures.

The PITCHFORK supports signing with XEDDSA a signature mechanism also
used in the SIGNAL protocol, it is based on elliptic curves. The
message to be signed is expected on the standard input, and the
signature is output to standard output:

`echo "sign me" | pitchfork sign >signature`

A signature is 64 bytes long, enough to put into a tweet if you want.

### Verifying short signatures

Verification of XEDDSA signatures also happens via standard input,
here you have to send first the binary signature and then the signed
message:

`{ cat signature; echo "sign me" ; } | pitchfork verify`

If the signature verifies correctly standard output will say so (also
indicating who signed the message), or indicate failure. The exit code
of the command will also be set accordingly. Furthermore the display
on the PITCHFORK will also display the outcome of the verification and
also the name of the person who was the signer of the message.

### Post-quantum signing

Additionally to short XEDDSA signatures the PITCHFORK also supports
SPHINCS-based post-quantum signatures. These signatures are much
bigger though, instead of only 64 bytes, these signatures are 44100
bytes long, not quite fitting in a tweet ;) But they should be still
unforgeable when the quantumcalypse descents onto us.

Invocation is similar to the short signatures, the message to be
signed is expected on standard input, the signature is sent to
standard output:

`echo "sign me" | pitchfork pqsign >pqsign`

Be warned post-quantum signatures take quite some time, expect a few
seconds until they're finished.

### Verifying SPHINCS signatures

For verifying a SPHINCS pubkey you don't need a PITCHFORK, as it would
mean the PITCHFORK would need to store the public key for your peer,
each such key is a bit bigger than 1KB, eating up the storage
quickly. So you have to supply the sphincs key when verifying
yourself. Your peers should have sent you their public sphincs key,
which can be exported like this:

`pitchfork getpub sphincs >pqpub`

If you have all three components for verification:

  1. the public SPHINCS key: `pqpub`
  2. the signature: `pqsign`
  3. the signed message: "sign me"

then you can provide all of them in this order over stdin to
`pitchfork` for verification:

`{ cat pqpub; cat pqsign; echo "sign me" ; } | pitchfork pqverify`

The output will indicate succeess or failure as will the exit code of
`pitchfork`.

### Anonymous One-way Encryption

If you don't have a PITCHFORK but want to send a one-way encrypted
message to someone who has, you can use the *anonymous one-way
encryption* mode of `pitchfork` to do so. This is useful to blow the
whistle or to send messages to journalists. All you need is the public
key of the recipient which they have to export and publish. It works
like this then:

`{ cat pubkey ; echo "hello stranger" ; } | pitchfork ancrypt >ancrypted`

You can then send `ancrypted` to the recipient, who will be able to
read this message.

### Decrypting Anonymous one-way messages.

When you receive an *anonymous one-way* message, you can decrypt it in
the following way:

` pitchfork andecrypt <ancrypted`

As always the encrypted message is expected on standard input, and the
unencrypted result is output to standard output.

### Sending Axolotl messages

The SIGNAL protocol is previously known as the Axoltl protocol, we use
this name because our output is not compatible with the original
SIGNAL messenger. Sending messages between two PITCHFORKs which have
exchanged keys either via the built-in radio, or using the
*kex-respond-end* commands over the internet can be done by piping
some message over standard input:

`echo 'Bob: 1<3u Alice' | pitchfork send Bob >ciphertext`

You have to provide the name of the key of the recipient to
`pitchfork`, in the example here the recipient is a key called `Bob`.

### Decrypting Axolotl messages

Decrypting incoming Axolotl message is quite simple, just pipe them
into `pitchfork`, and expect the plaintext on standard output:

`pitchfork recv <ciphertext`

### Shared-key encryption

We recommend to always use Axolotl encryption, but those messages can
only decrypted for some limited time (depending on how frequently you
exchange messages), if you need encryption that lasts "forever" and
can be always decrypted again, then we offer this shared-key encryption,
which is much less safe in case your key ever gets compromised. Again,
it's quite simple you pipe the message into `pitchfork` and get the
encrypted message on standard output:

`echo 'PITCHFORK!!5!' | pitchfork encrypt Bob >cipher`

Again the recipients key must be provided on the command line, in this
case the recipient key is called `Bob`.

### Decrypting shared-key messages

Decrypting shared-key messages works by providing the encrypted
message on standard input, and the plaintext will be output on
standard output:

`pitchfork decrypt <cipher`

## kmleon

`kmleon` (pronounced key-meleon) is tool that dispatches crypto
operations betweend various backends. It is intended to replace your
gpg binary so that tools traditionaly depending on gnupg (like
mutt/enigmail) can use other (better?) cryptographic backends.

When `kmleon` is used to encrypt messages it checks if there are keys
available for the recipients for the supported backends (currently
PITCHFORK, opmsg, gnupg, in this order), it then dispatches the
operation to the approprate backend. Note currently only one backend
per message is supported, all recipients have to have keys in the
selected backend. When decrypting/verifying messages the ASCII armor
headers are used to distinguish between the backends to be used.

## pitchfork.sh

`pitchfork.sh` is a convenience wrapper around `pitchfork`. It handles
conversion of hex key ids into key names used by `pitchfork`, and it
caches the list of keys on a pitchfork, so the user does not have to
approve the listing of the keys many times during the operation of
kmleon.

## ASCII (de)armoring

`pitchfork` only outputs binary, in many cases you want this ASCII
armored, for this the pitchfork toolset provides two simple wrappers:
armor and dearmor. Both tools can be prepended to any command
emitting/expecting ASCII-armored output/input respectively.

### armor

`armor` takes a "header identifier" and command which outputs some
binary as it's parameters, and encodes this output using the
`base64(1)` tool and wraps it with the header identifier.

#### armor example

`armor msg /bin/dd if=/dev/zero count=1 bs=16 2>/dev/null`

outputs:

```
----- begin msg armor -----
AAAAAAAAAAAAAAAAAAAAAA==
----- end msg armor -----
```

As you can see 16 zero bytes are base64 encoded and wrapped in "begin
msg" and "end msg" lines, the header identifier in this case "msg".

#### dearmor example

`dearmor` again takes a header identifier and a command which expects
some binary input as parameters as its input. dearmor then seeks in
standard input until it finds the "begin" line with the header
identifier and base64 decodes this until the according "end" line,
outputing the decoded binary on standard output to the progam provided
on the commandline.

#### dearmor example

```
dearmor msg hexdump <<EOT
----- begin msg armor -----
AAAAAAAAAAAAAAAAAAAAAA==
----- end msg armor -----
EOT
```

would output:

```
0000000 0000 0000 0000 0000 0000 0000 0000 0000
0000010
```

## lib/libpitchfork.so

This is a simple library that you can use to access your PITCHFORK, to
write better cli tools, or even GUI tools. It is needed for
`pitchfork` to work, which really is just a simple command-line
wrapper around `libpitchfork.so`.
