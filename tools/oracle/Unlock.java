import org.cryptomator.cryptofs.CryptoFileSystem;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Offline oracle for the vault: unlock it on the desktop JVM with the official cryptofs and dump
 * the mapping between what the user sees and what is stored in the cloud.
 *
 * <p>Two jobs:
 * <ol>
 *   <li>Answer "is this passphrase right?" without involving the phone.</li>
 *   <li>Produce the expected plaintext of every ciphertext file, so anything later read on the
 *       device can be checked against it byte for byte.</li>
 * </ol>
 *
 * <p>Everything printed is deliberately ASCII: the output is a manifest to be diffed, and ciphertext
 * is binary. Contents are base64, and the manifest is grep-safe as a result.
 *
 * <p>This is reconnaissance tooling and is NOT shipped in the module. The module cannot use cryptofs
 * (it needs java.nio.file, guava, jackson and a local filesystem), so the module calls cryptolib
 * directly and this program is what says whether the module's own traversal agrees with the
 * official one.
 *
 * Usage: Unlock &lt;vaultDir&gt; &lt;passphrase&gt;
 */
public final class Unlock {

    /** Above this cleartext size the manifest prints only the digest, not the content. */
    private static final int INLINE_LIMIT = 256;

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: Unlock <vaultDir> <passphrase>");
            System.exit(2);
        }
        final Path vault = Paths.get(args[0]).toAbsolutePath().normalize();
        final String passphrase = args[1];
        if (!Files.isDirectory(vault)) {
            System.err.println("not a directory: " + vault);
            System.exit(2);
        }
        final Path masterkeyFile = vault.resolve("masterkey.cryptomator");
        final Path ciphertextRoot = vault.resolve("d");

        System.out.println("vault        : " + vault);
        System.out.println("cipher root  : " + ciphertextRoot);

        // The byte[] argument is NOT the vault version and NOT the vault config. It is a PEPPER --
        // extra key material fed into scrypt -- and for every standard vault it must be EMPTY.
        // Passing something else does not raise an argument error: it changes the KEK, so AES-KW
        // unwrapping fails and the call comes back as InvalidPassphraseException, indistinguishable
        // from a genuinely wrong passphrase. (readAllegedVaultVersion is an unrelated static helper
        // that reads the masterkey file's own "version" field.)
        final byte[] pepper = new byte[0];
        final MasterkeyLoader loader = uri -> {
            MasterkeyFileAccess access = new MasterkeyFileAccess(pepper, new SecureRandom());
            try {
                return access.load(masterkeyFile, passphrase);
            } catch (Exception e) {
                throw new RuntimeException("masterkey load failed", e);
            }
        };

        CryptoFileSystemProperties props = CryptoFileSystemProperties.cryptoFileSystemProperties()
                .withKeyLoader(loader)
                .withCipherCombo(CryptorProvider.Scheme.SIV_GCM)
                .withShorteningThreshold(220)
                .build();

        CryptoFileSystem fs;
        try {
            // cryptofs is given the VAULT root, not d/: CryptoFileSystems reads
            // <vault>/vault.cryptomator itself and then descends into <vault>/d.
            fs = CryptoFileSystemProvider.newFileSystem(vault, props);
        } catch (Throwable t) {
            System.out.println("RESULT: UNLOCK FAILED");
            t.printStackTrace(System.out);
            System.exit(1);
            return;
        }
        System.out.println("RESULT: UNLOCK OK");

        // The cleartext root is "/" *inside* the CryptoFileSystem. getPathToVault() is not that:
        // it answers "where is the vault stored", i.e. it hands back a path on the default
        // filesystem, and walking it walks the raw ciphertext directory.
        Path root = fs.getPath("/");
        System.out.println("cleartext    : " + root + " (provider " + root.getFileSystem().provider().getScheme() + ")");
        System.out.println("pathToVault  : " + fs.getPathToVault());

        // ------------------------------------------------------- walk ---------
        List<Path> all = new ArrayList<>();
        try (Stream<Path> s = Files.walk(root)) {
            s.forEach(all::add);
        }
        all.sort(Comparator.naturalOrder());

        List<String> ciphertextSeen = new ArrayList<>();
        int dirs = 0, files = 0;
        long bytes = 0;
        System.out.println();
        System.out.println("=== manifest: cleartext <-> ciphertext ===");
        for (Path p : all) {
            String rel = root.relativize(p).toString().replace('\\', '/');
            if (rel.isEmpty()) {
                rel = "/";
            }
            boolean isDir = Files.isDirectory(p);
            String ctRel;
            try {
                Path ct = fs.getCiphertextPath(p);
                ctRel = ct == null ? "-" : vault.relativize(ct).toString().replace('\\', '/');
                if (ct != null) {
                    ciphertextSeen.add(ctRel);
                }
            } catch (Throwable t) {
                ctRel = "!" + t.getClass().getSimpleName();
            }
            if (isDir) {
                dirs++;
                System.out.println("DIR   " + rel + "  <-  " + ctRel);
            } else {
                files++;
                byte[] b = Files.readAllBytes(p);
                bytes += b.length;
                // Only inline the cleartext when it is small enough to be useful in a diff. The
                // P0-D fixture has a 1 MiB file, and inlining it turned a readable manifest into a
                // 1.5 MB one. sha256 is the comparison that actually matters for sizeable files.
                String payload = b.length <= INLINE_LIMIT
                        ? " b64=" + b64(b)
                        : " b64=<" + b.length + " bytes omitted>";
                System.out.println("FILE  " + rel + "  <-  " + ctRel
                        + "  size=" + b.length + " sha256=" + sha256(b) + payload);
            }
        }
        System.out.println("totals: " + dirs + " dir(s), " + files + " file(s), " + bytes + " cleartext byte(s)");

        // ------------------------------------------- ciphertext inventory -----
        // What is actually stored, including what has no cleartext counterpart at all: every
        // directory carries a dirid.c9r, and nothing the user sees corresponds to it.
        System.out.println();
        System.out.println("=== ciphertext inventory: " + ciphertextRoot + " (on disk) ===");
        List<Path> ctAll = new ArrayList<>();
        try (Stream<Path> s = Files.walk(ciphertextRoot)) {
            s.forEach(ctAll::add);
        }
        ctAll.sort(Comparator.naturalOrder());
        for (Path p : ctAll) {
            String rel = ciphertextRoot.relativize(p).toString().replace('\\', '/');
            if (rel.isEmpty()) {
                continue;
            }
            if (Files.isDirectory(p)) {
                System.out.println("d " + rel);
            } else {
                byte[] b = Files.readAllBytes(p);
                boolean mapped = ciphertextSeen.contains("d/" + rel);
                System.out.println("f " + rel + "  size=" + b.length
                        + (mapped ? "  [cleartext counterpart]" : "  [NO cleartext counterpart]"));
            }
        }
        fs.close();
    }

    private static String sha256(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
