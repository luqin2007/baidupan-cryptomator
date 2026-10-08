# P2 offline harness

Runs the **module's own** vault traversal (`module/src/com/luqin/bdcrypto/vault/`) against a vault on
this machine and checks the result against the official Cryptomator implementation.

```bash
bash tools/p2/p2.sh walk     /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
bash tools/p2/p2.sh check    /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
bash tools/p2/p2.sh negative /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
```

`walk` prints the manifest. `check` runs `tools/oracle/oracle.sh unlock` on the same vault, reduces
both manifests to one normalised line per entry (kind, cleartext path, ciphertext path, cleartext
size), sorts them, and diffs — exit code 0 only when the module's tree is *the same tree* cryptofs
produces. Current result on the P0-D fixture:

```
P2 CHECK OK: 29 entries match cryptofs
  dirs : 8
  files: 21
  T 8 dir(s), 21 file(s), 1155600 cleartext byte(s)
```

`negative` is what keeps that from being a rubber stamp: it copies the vault, provokes each failure
mode the format has, and requires the specific message each one should produce (a check that has
only ever seen a healthy vault is indistinguishable from one that always says ok).

```
ok  wrong passphrase             VAULT ERROR: key unwrap failed its integrity check (the passphrase does not belong to this vault)
ok  tampered entry name          VAULT ERROR: entry name does not authenticate under directory '76f46e85-…'
ok  tampered vault config        VAULT ERROR: vault.cryptomator's HS256 signature does not verify (…)
ok  wrong dirid.c9r size         ! dirid.c9r of 中文目录 is 100 bytes; an id of 36 bytes should have made it 132
P2 NEGATIVE OK: every provoked fault was detected
```

## Why it is built this way

**It compiles the module's sources, not a copy of them.** `p2.sh` compiles
`module/src/com/luqin/bdcrypto/vault/**` — the same files `module/build.sh` dexes — with **no
`android.jar` on the classpath**. Two consequences, both intentional: an Android import creeping into
the traversal fails the build here instead of on the phone, and the code that was diffed against
cryptofs is byte-for-byte the code that ships.

**Its classpath is exactly the module's two jars** (`cryptolib-2.2.2`, `siv-mode-1.6.1`) plus the
one guava class cryptolib reaches for. No gson, no guava, no cryptofs. The desktop oracle has all of
those, so it would happily succeed on code the device cannot run — this harness has nothing the
module does not have, which is why it is the acceptance test and the oracle is only the referee.

**Content is out of scope.** P2 decrypts names, not file contents: the comparison covers the tree
(directories, cleartext names, ciphertext counterparts) and cleartext sizes, which are derived from
the measured size model rather than from the bytes. Byte-for-byte content comparison is P3, and that
is where `tools/oracle`'s `sha256`/`b64` columns will finally be compared too.

## What P2 does not cover yet

- **Nothing on the device calls this yet.** The traversal is verified offline; wiring it into the
  file page needs the ciphertext to be readable from inside the app process first.
- **Content decryption** (the 68-byte file header, chunked AES-GCM) is P3.
- The harness prints `warnings: N` and exits non-zero if the traversal had to skip or contradict
  anything, so "0 warnings" is part of the result rather than a claim about it.
