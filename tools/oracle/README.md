# Offline vault oracle

Two reference programs that unlock a Cryptomator vault **on this machine**, using the official
`cryptolib` + `cryptofs` jars from a local Cryptomator installation.

They exist because the module cannot ship `cryptofs` (it needs `java.nio.file`, guava, jackson,
caffeine and a real local filesystem) and must implement the directory traversal itself. These
programs are the authority that implementation is checked against, and they produce the expected
plaintext of every ciphertext file — which is what makes a byte-for-byte comparison against
whatever the phone produces possible at all.

```bash
tools/oracle/oracle.sh check  /d/cryptomator/baidu '<passphrase>'   # is the passphrase right?
tools/oracle/oracle.sh unlock /d/cryptomator/baidu '<passphrase>'   # cleartext <-> ciphertext map
```

`check` is deliberately independent of `MasterkeyFileAccess.load`: it redoes scrypt, both AES-KW
unwraps and the `versionMac` check by hand. That API reports only `InvalidPassphraseException`,
which is also exactly what a wrong constructor argument looks like — see below.

`unlock` prints a manifest that is pure ASCII (contents base64) so it can be diffed and grepped.
Paths, sizes, sha256 and the ciphertext counterpart of every cleartext entry are all in it.

## Requirements

A local Cryptomator install for its jars (`CRYPTOMATOR_MODS` to point elsewhere), and a **JDK 25+**
(`ORACLE_JAVA_HOME` to point at one that is not on `PATH`). The JDK requirement is not arbitrary:
`cryptolib` is Java 8 bytecode — which is precisely why it can be dexed into an Android module —
but `cryptofs` is class file version 69, and JDK 21 refuses it outright with
`class file has wrong version 69.0, should be 65.0`.

## Two traps these programs exist to make visible

**`MasterkeyFileAccess(byte[], SecureRandom)` — the array is a *pepper*, and it must be empty.**
It is not the vault version and not the vault config (`readAllegedVaultVersion` is an unrelated
static helper that reads a *masterkey file*'s own `version` field). A non-empty pepper changes the
KEK, so AES-KW unwrapping fails, and the call comes back as `InvalidPassphraseException` —
byte-for-byte indistinguishable from a genuinely wrong passphrase. Passing the masterkey file's
contents here cost an hour of "the password must be wrong".

**`CryptoFileSystemProvider.newFileSystem` takes the *vault root*, not `d/`** — it reads
`<vault>/vault.cryptomator` itself and then descends into `<vault>/d`. And the cleartext root is
`fs.getPath("/")`, not `fs.getPathToVault()`: the latter answers "where is the vault stored" and
hands back a path on the *default* filesystem, so walking it walks raw ciphertext.
