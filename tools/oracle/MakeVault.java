import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds a fresh Cryptomator test vault so that P2 has something to be wrong about.
 *
 * <p>Why this exists: the vault we have ({@code D:/cryptomator/baidu}) holds one directory and one
 * 820-byte file. Validating a from-scratch traversal against it would only prove the happy path --
 * there is no overlong name to exercise the .c9s shortening scheme, no nested directory, no file
 * crossing the 32 KiB chunk boundary, no empty file, no case-collision. Those are exactly the parts
 * of the format that are easy to get subtly wrong and impossible to notice on a sparse vault.
 *
 * <p>Creation goes through {@link CryptoFileSystemProvider#initialize}, the same entry point the
 * desktop app uses, so the result is a real vault rather than something that merely opens in the
 * one code path we happen to test. That call is also where three non-obvious facts live, all of
 * which the module will have to reproduce at unlock time:
 *
 * <ul>
 *   <li>the ROOT directory id is the EMPTY STRING, and its on-disk location is
 *       {@code d/<hashDirectoryId("")[0:2]>/<rest>} -- the directory is not simply named after an id
 *       the way every other directory is;</li>
 *   <li>{@code vault.cryptomator} is not JSON: it is an HS256 JWT carrying
 *       {@code format/cipherCombo/shorteningThreshold}, signed with the masterkey's own encoded
 *       bytes, with {@code kid} set to the masterkey URI;</li>
 *   <li>the root directory still gets a {@code dirid.c9r}, written through {@code DirectoryIdBackup}
 *       even though the id it holds is empty.</li>
 * </ul>
 *
 * <p>Keys are freshly generated and the passphrase is the fixture's own, so a module that happened
 * to work only because something from the other vault was hardcoded cannot pass here.
 *
 * <p>Requires JDK 25 (cryptofs is class file version 69). Run through oracle.sh, which finds the
 * jars and the JDK: {@code oracle.sh make <vaultDir> <passphrase>}.
 *
 * <p>Refuses to write into a directory that already holds a vault.cryptomator, so a mistyped path
 * cannot destroy an existing vault.
 */
public final class MakeVault {

    /**
     * The fixture must match the format the target app will actually be pointed at; validating P2
     * against anything else would be validating the wrong thing.
     */
    private static final CryptorProvider.Scheme CIPHER_COMBO = CryptorProvider.Scheme.SIV_GCM;
    private static final int SHORTENING_THRESHOLD = 220;

    private static final String MASTERKEY_FILENAME = "masterkey.cryptomator";

    /**
     * The value real vaults carry in the JWT "kid" header. Decoded straight out of a vault the
     * desktop app created rather than inferred from the name of the file sitting next to it.
     */
    private static final URI MASTERKEY_URI = URI.create("masterkeyfile:" + MASTERKEY_FILENAME);

    /** Cryptomator's cleartext chunk size; the boundary is where the content layer gets interesting. */
    private static final int CHUNK = 32 * 1024;

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: MakeVault <vaultDir> <passphrase>");
            System.exit(2);
        }
        final Path vault = Paths.get(args[0]).toAbsolutePath().normalize();
        final String passphrase = args[1];

        if (Files.exists(vault.resolve("vault.cryptomator"))) {
            System.err.println("refusing to overwrite an existing vault: " + vault);
            System.err.println("(delete it yourself first, or pick another directory)");
            System.exit(3);
        }
        Files.createDirectories(vault);

        // The byte[] is a PEPPER, not a version and not a salt. Standard vaults use an empty one;
        // anything else changes the KEK and turns "wrong parameter" into what looks like "wrong
        // passphrase". See tools/oracle/README.md.
        final byte[] pepper = new byte[0];
        final SecureRandom random = new SecureRandom();

        // -------------------------------------------------- masterkey, before anything else ----
        // initialize() below loads the masterkey through the key loader, so it has to be on disk by
        // then. This is also the only step initialize() does NOT do for us.
        Masterkey generated = Masterkey.generate(random);
        try {
            MasterkeyFileAccess access = new MasterkeyFileAccess(pepper, random);
            access.persist(generated, vault.resolve(MASTERKEY_FILENAME), passphrase);
        } finally {
            generated.close();
        }

        CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                .withKeyLoader(uri -> {
                    MasterkeyFileAccess access = new MasterkeyFileAccess(pepper, new SecureRandom());
                    try {
                        return access.load(vault.resolve(MASTERKEY_FILENAME), passphrase);
                    } catch (Exception e) {
                        throw new RuntimeException("masterkey load failed", e);
                    }
                })
                .withCipherCombo(CIPHER_COMBO)
                .withShorteningThreshold(SHORTENING_THRESHOLD)
                .withMasterkeyFilename(MASTERKEY_FILENAME)
                .build();

        // ------------------------------------------------------------------ create the vault ----
        CryptoFileSystemProvider.initialize(vault, props, MASTERKEY_URI);

        // ------------------------------------------------------------------------ content ----
        List<String> written = new ArrayList<>();
        long total = 0;

        CryptoFileSystem fs = CryptoFileSystemProvider.newFileSystem(vault, props);
        try {
            Path root = fs.getPath("/");

            // --- names that differ only in case, plus a hidden file ---
            write(fs, root, "/中文名.txt", content("中文名.txt", 40), written);
            write(fs, root, "/with space.txt", content("with space.txt", 40), written);
            write(fs, root, "/UPPER.txt", content("UPPER.txt", 64), written);
            write(fs, root, "/upper.txt", content("upper.txt", 64), written);
            write(fs, root, "/.hidden.txt", content(".hidden.txt", 16), written);
            write(fs, root, "/emoji-🎉-✓.txt", content("emoji", 32), written);
            write(fs, root, "/特殊字符-!@#$%^&()_+-=[]{};',~.txt", content("specials", 32), written);

            // --- the empty case, where "encrypted size" is not "cleartext size + overhead" ---
            write(fs, root, "/empty.txt", new byte[0], written);

            // --- the chunk boundary, from both sides ---
            write(fs, root, "/chunk-below.bin", content("chunk-below", CHUNK - 1), written);
            write(fs, root, "/chunk-exact.bin", content("chunk-exact", CHUNK), written);
            write(fs, root, "/chunk-above.bin", content("chunk-above", CHUNK + 1), written);
            write(fs, root, "/chunk-1MiB.bin", content("chunk-1MiB", 1024 * 1024), written);
            write(fs, root, "/zeroes.bin", new byte[8 * 1024], written);

            // --- overlong names. The threshold measures the ENCODED length: ciphertext is
            //     cleartext + a 16-byte tag, base64url, plus ".c9r". At 140 characters we are still
            //     under 220 and the name survives as-is; at 200 the .c9s shortening scheme must kick
            //     in. Both are here so the manifest shows where the switch actually happens rather
            //     than leaving it to be derived from the spec.
            write(fs, root, "/" + repeat("n140-", 140) + ".txt", content("n140", 48), written);
            write(fs, root, "/" + repeat("n200-", 200) + ".txt", content("n200", 48), written);

            // --- the same basename in two directories: name encryption is scoped per directory, so
            //     these two must NOT end up sharing a ciphertext name. ---
            write(fs, root, "/重复.txt", content("root-dup", 24), written);
            write(fs, root, "/同名/重复.txt", content("nested-dup", 24), written);

            // --- nesting, including a Chinese directory name ---
            write(fs, root, "/中文目录/文件.txt", content("cn-dir-file", 24), written);
            write(fs, root, "/深层/一级/二级/三级/deep.txt", content("deep", 24), written);
            write(fs, root, "/深层/一级/二级/三级/另一份.txt", content("deep2", 24), written);

            // --- an overlong DIRECTORY name: shortening applies to directories too ---
            write(fs, root, "/" + repeat("d190-", 190) + "/inside.txt", content("inside", 24), written);
        } finally {
            fs.close();
        }

        System.out.println("=== created vault " + vault + " ===");
        System.out.println(MASTERKEY_FILENAME + "   (passphrase-protected JSON, scrypt + AES-KW)");
        System.out.println("vault.cryptomator     (HS256 JWT, kid=" + MASTERKEY_URI + ")");
        System.out.println();
        System.out.println("=== fixture content as the user sees it ===");
        for (String line : written) {
            System.out.println(line);
            int eq = line.lastIndexOf("size=");
            if (eq > 0) {
                total += Long.parseLong(line.substring(eq + 5, line.indexOf(' ', eq + 5)));
            }
        }
        System.out.println("totals: " + written.size() + " entr(ies), " + total + " cleartext byte(s)");
        System.out.println();
        System.out.println("Next:  oracle.sh unlock " + vault + " '<passphrase>'");
        System.out.println("       (the manifest it prints is this fixture's expected answer)");
    }

    private static void write(CryptoFileSystem fs, Path root, String cleartext, byte[] bytes,
                              List<String> log) throws Exception {
        Path p = fs.getPath(cleartext);
        Path parent = p.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(p, bytes);
        // Read it straight back through the vault: a silent short write must not pass for success.
        byte[] back = Files.readAllBytes(p);
        if (!Arrays.equals(bytes, back)) {
            throw new IllegalStateException("round-trip mismatch for " + cleartext);
        }
        log.add("FILE  " + cleartext + "  size=" + bytes.length + " sha256=" + sha256(bytes));
    }

    /**
     * Deterministic bytes, so re-running the generator yields identical cleartext and a manifest
     * diff between two fixtures is empty. The vault id and keys are random, so ciphertext names do
     * differ per run -- which is why the manifest is regenerated rather than stored.
     */
    private static byte[] content(String name, int len) throws Exception {
        byte[] seed = ("bdcrypto-fixture:" + name).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[len];
        int off = 0;
        int block = 0;
        while (off < len) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(seed);
            md.update((byte) (block >>> 24));
            md.update((byte) (block >>> 16));
            md.update((byte) (block >>> 8));
            md.update((byte) block);
            byte[] d = md.digest();
            int n = Math.min(d.length, len - off);
            System.arraycopy(d, 0, out, off, n);
            off += n;
            block++;
        }
        return out;
    }

    private static String repeat(String unit, int total) {
        StringBuilder sb = new StringBuilder(total);
        while (sb.length() < total) {
            sb.append(unit);
        }
        return sb.substring(0, total);
    }

    private static String sha256(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
