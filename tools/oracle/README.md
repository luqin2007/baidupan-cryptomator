# Offline vault oracle

Three programs that work on a Cryptomator vault **on this machine**, using the official
`cryptolib` + `cryptofs` jars from a local Cryptomator installation.

They exist because the module cannot ship `cryptofs` (it needs `java.nio.file`, guava, jackson,
caffeine and a real local filesystem) and must implement the directory traversal itself. These
programs are the authority that implementation is checked against, and they produce the expected
plaintext of every ciphertext file — which is what makes a byte-for-byte comparison against
whatever the phone produces possible at all.

```bash
tools/oracle/oracle.sh check  /d/cryptomator/baidu '<passphrase>'   # is the passphrase right?
tools/oracle/oracle.sh unlock /d/cryptomator/baidu '<passphrase>'   # cleartext <-> ciphertext map
tools/oracle/oracle.sh make   /d/cryptomator/p0d-fixture '<passphrase>'   # build the test fixture
```

`check` is deliberately independent of `MasterkeyFileAccess.load`: it redoes scrypt, both AES-KW
unwraps and the `versionMac` check by hand. That API reports only `InvalidPassphraseException`,
which is also exactly what a wrong constructor argument looks like — see below.

`unlock` prints a manifest that is pure ASCII (contents base64) so it can be diffed and grepped.
Paths, sizes, sha256 and the ciphertext counterpart of every cleartext entry are all in it.
Cleartext is inlined only up to 256 bytes; past that only the digest is printed, because the P0-D
fixture contains a 1 MiB file and inlining it turned a readable manifest into a 1.5 MB one.

`make` builds the P0-D test fixture (see below). It writes fresh keys and refuses to touch a
directory that already holds a `vault.cryptomator`.

## The P0-D test fixture

`D:/cryptomator/baidu` holds **one directory and one 820-byte file**, which is not enough to
validate a traversal implementation: nothing in it exercises the `.c9s` shortening scheme, a
nested directory, the 32 KiB chunk boundary, or an empty file — the parts of the format that are
easy to get subtly wrong and impossible to notice on a sparse vault.

```bash
tools/oracle/oracle.sh make /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
tools/oracle/oracle.sh unlock /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
```

That is the fixture's passphrase; it protects synthetic data only. The vault it produces has 8
directories and 21 files (1,155,600 cleartext bytes) covering Chinese names, a space, a hidden
file, an emoji name, characters that are illegal on Windows, case-only collisions, an empty file,
a 1 MiB file, the chunk boundary from both sides, an overlong file name, an overlong directory
name, and the same basename in two directories. Cleartext is deterministic (derived from the
path), so two fixtures produce identical cleartext and an empty manifest diff; keys and the vault
id are random, so ciphertext names differ per run, which is why the manifest is regenerated rather
than stored.

`make` goes through `CryptoFileSystemProvider.initialize`, the same entry point the desktop app
uses, rather than writing the vault's files by hand. Three facts live in that one call, all of
which the module will have to reproduce:

- the **root directory id is the empty string**, and its on-disk location is
  `d/<hashDirectoryId("")[0:2]>/<rest>` — the root is *not* named after an id the way every other
  directory is, so it cannot be located without asking cryptolib to hash the empty string;
- `vault.cryptomator` is **not JSON**: it is an HS256 JWT with claims
  `format`/`cipherCombo`/`shorteningThreshold`, signed with `masterkey.getEncoded()`, `kid` set to
  the masterkey URI (`masterkeyfile:masterkey.cryptomator`);
- the content directory of a vault must *already exist* before `newFileSystem` will open it
  (`ContentRootMissingException` otherwise); `initialize` is what creates it.

## What the on-disk layout actually looks like

Measured on the fixture, not derived from the spec:

```
d/<hash[0:2]>/<rest>/                 content directory of a directory (hash = hashDirectoryId(dirId))
    dirid.c9r                         this directory's OWN id, encrypted
    <b64url name>.c9r                 a file: the name is the encrypted cleartext name
    <b64url name>.c9r/dir.c9r         a SUBDIRECTORY: a directory named after the encrypted name,
                                      whose dir.c9r holds the child's id in PLAINTEXT (a UUID)
    <b64url short>.c9s/name.c9s       an overlong name, shortened: the real encrypted name lives here
    <b64url short>.c9s/contents.c9r   ...and if it was a file, so does its content
```

Two things here contradict the intuitive reading of the format and are worth stating plainly:

- a **directory id is a UUID** (36 ASCII characters), not a hash — `hashDirectoryId` is what turns
  it into the 32-character base32 name used under `d/`. The child's id sits in the parent in
  **cleartext**; it is the *name* that is encrypted.
- an overlong name turns a **file into a directory** (`.c9s/`), with the content in a separate
  `contents.c9r`. Code that assumes "a ciphertext file ends in .c9r" misses this entirely.

Content files have a size model that is exact for every size tested:

```
on-disk size = 68 + 28 * ceil(cleartext / 32768) + cleartext
```

so 0 → 68, 24 → 120, 32768 → 32864, 32769 → 32893, 1048576 → 1049540. The 28 bytes per chunk
matches a 12-byte nonce plus a 16-byte GCM tag; the 68-byte fixed part is what is left over. Note
`dirid.c9r` **breaks this**: an empty directory id still yields 96 bytes, i.e. one chunk *was*
written, where a 0-byte file content yields 68 with no chunk at all. The internal layout of the
68-byte part has not been resolved yet — that is P3 work, and it needs cryptolib to decrypt rather
than arithmetic to guess.

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
