package com.luqin.bdcrypto.vault;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An unlocked vault: passphrase + ciphertext in, the user's directory tree out.
 *
 * <p>This is the module's own implementation, and it has to exist because cryptofs cannot be dexed
 * (it needs java.nio.file, guava, jackson and a real local filesystem — Java 25 bytecode on top).
 * cryptolib can be dexed and is used for the primitives that are dangerous to reimplement (scrypt,
 * AES-SIV). Everything between those two layers — where a directory's id comes from, what a
 * shortened name looks like, which file holds a subdirectory's id — is in this package, because
 * that is exactly the part no library will do for us.
 *
 * <p>The traversal is over a {@link CipherStore}, not over a device path, so the same code walks
 * the fixture on a desktop JVM and the cloud's ciphertext on the phone.
 *
 * <p>Layout (measured on the P0-D fixture, docs/recon.md §12.3):
 *
 * <pre>
 * d/&lt;h[0:2]&gt;/&lt;h[2:]&gt;/            a directory's own entries, h = hashDirectoryId(dirId)
 *     dirid.c9r                    this directory's id, encrypted (not needed to walk)
 *     &lt;b64url name&gt;.c9r            a file
 *     &lt;b64url name&gt;.c9r/dir.c9r    a SUBDIRECTORY: the child's id, in cleartext
 *     &lt;b64url short&gt;.c9s/name.c9s  an overlong name: the real (encrypted) name is in here
 *     &lt;b64url short&gt;.c9s/contents.c9r   …and if it was a file, its content
 * </pre>
 *
 * <p>Two things in there are worth stating out loud because they are traps. A directory id is a
 * <b>UUID in cleartext</b>, not a hash — the hash is only how the id names a directory under
 * {@code d/}. And an overlong name turns a <b>file into a directory</b> ({@code .c9s/}), so code
 * that assumes "ciphertext files end in .c9r" loses those entries without noticing.
 */
public final class Vault {

    static final String MASTERKEY_FILE = "masterkey.cryptomator";
    static final String CONFIG_FILE = "vault.cryptomator";
    static final String CONTENT_DIR = "d";
    static final String DIRID_FILE = "dirid.c9r";
    static final String DIR_FILE = "dir.c9r";
    static final String NAME_FILE = "name.c9s";
    static final String CONTENTS_FILE = "contents.c9r";

    private static final String C9R = ".c9r";
    private static final String C9S = ".c9s";

    /** Longest directory id that could be legitimate: a UUID is 36 characters. */
    private static final int MAX_DIR_ID = 64;

    private final CipherStore store;
    private final MasterkeyFile.Keys keys;
    private final VaultConfigFile config;
    private final VaultCipher cipher;
    private final List<String> warnings = new ArrayList<String>();

    private Vault(CipherStore store, MasterkeyFile.Keys keys, VaultConfigFile config) {
        this.store = store;
        this.keys = keys;
        this.config = config;
        this.cipher = new VaultCipher(keys.encKey, keys.macKey);
    }

    /** Unlocks a vault that is a directory on a local filesystem. */
    public static Vault open(File vaultRoot, String passphrase) throws IOException {
        return open(new FileCipherStore(vaultRoot), passphrase);
    }

    /**
     * Unlocks a vault behind any {@link CipherStore}.
     *
     * @throws VaultException wrong passphrase, unsupported format, or an unreadable vault
     */
    public static Vault open(CipherStore store, String passphrase) throws IOException {
        if (!store.exists(MASTERKEY_FILE)) {
            throw new VaultException("no " + MASTERKEY_FILE + " — this is not a vault root");
        }
        String masterkeyJson = new String(store.read(MASTERKEY_FILE), StandardCharsets.UTF_8);
        MasterkeyFile.Keys keys = MasterkeyFile.parse(masterkeyJson, passphrase);

        if (!store.exists(CONFIG_FILE)) {
            throw new VaultException("no " + CONFIG_FILE + " next to " + MASTERKEY_FILE);
        }
        String configJwt = new String(store.read(CONFIG_FILE), StandardCharsets.UTF_8);
        VaultConfigFile config = VaultConfigFile.parse(configJwt, keys.encoded());

        return new Vault(store, keys, config);
    }

    public int format() {
        return config.format;
    }

    public String cipherCombo() {
        return config.cipherCombo;
    }

    public int shorteningThreshold() {
        return config.shorteningThreshold;
    }

    public int masterkeyVersion() {
        return keys.version;
    }

    public CipherStore store() {
        return store;
    }

    /** Where the root's entries live; only knowable after unlocking (it is key-dependent). */
    public String rootContentPath() throws IOException {
        return contentPath("");
    }

    /**
     * The vault-relative directory that holds {@code dirId}'s entries.
     *
     * <p>The device needs this to answer "the user is looking at {@code d/XY/…} — which directory
     * is that?": the answer is whatever dirId hashes to that path, so the path is what a session
     * records as it descends.
     */
    public String contentPath(String dirId) throws IOException {
        return cipher.contentPath(dirId);
    }

    /**
     * Cleartext name of one entry, given its on-disk name.
     *
     * @return null when the on-disk name carries no cleartext name to decrypt: files the format
     *     uses for its own bookkeeping ({@link #isInternal}), a shortened name (whose real name is
     *     inside it, see {@link #names}), or something that is not an entry at all
     */
    public String name(String dirId, String ciphertextName) throws IOException {
        if (isInternal(ciphertextName)) {
            // dirid.c9r / dir.c9r / name.c9s / contents.c9r: the format's own bookkeeping, not an
            // entry, and `dirid` is not even valid base64 — decrypting it would throw.
            return null;
        }
        if (ciphertextName.endsWith(C9R)) {
            return cipher.decryptName(strip(ciphertextName, C9R), dirId);
        }
        return null;
    }

    /**
     * Decrypts the names of one directory's entries, in the order given.
     *
     * <p>This is the entry point for the file page: the app already knows the ciphertext names of
     * the directory it is drawing, so the module only has to translate them. It deliberately needs
     * nothing but the names — no listing, no downloads — which is what makes it usable where a full
     * {@link #walk()} is not (on the device the ciphertext is remote, and only the directory being
     * browsed is available).
     *
     * <p>A shortened name ({@code .c9s}) comes back null: the real name lives in
     * {@code <name>.c9s/name.c9s}, which cannot be read until that folder is listed. Callers should
     * show the entry as unresolved rather than inventing a name for it.
     *
     * @throws VaultException a name that does not authenticate — the wrong directory id, or damage
     */
    public String[] names(String dirId, String[] ciphertextNames) throws IOException {
        String[] out = new String[ciphertextNames.length];
        for (int i = 0; i < ciphertextNames.length; i++) {
            out[i] = name(dirId, ciphertextNames[i]);
        }
        return out;
    }

    /** True for the files the format keeps for itself; a file page must not show them. */
    public static boolean isInternal(String name) {
        return DIRID_FILE.equals(name) || DIR_FILE.equals(name)
                || NAME_FILE.equals(name) || CONTENTS_FILE.equals(name);
    }

    /** Non-fatal contradictions found by the last {@link #walk()}: empty means the tree is clean. */
    public List<String> warnings() {
        return Collections.unmodifiableList(warnings);
    }

    /**
     * Walks the whole vault and returns every entry, the root first, then cleartext paths in order.
     *
     * <p>An entry whose name does not authenticate is fatal: at that point the directory id we are
     * using is wrong or the vault is damaged, and carrying on would produce a tree that looks
     * plausible and is not the user's.
     */
    public List<VaultEntry> walk() throws IOException {
        warnings.clear();
        List<VaultEntry> entries = new ArrayList<VaultEntry>();
        Set<String> seenDirIds = new HashSet<String>();
        Deque<Directory> pending = new ArrayDeque<Directory>();
        pending.add(new Directory("", "/"));

        while (!pending.isEmpty()) {
            Directory directory = pending.removeFirst();
            if (!seenDirIds.add(directory.id)) {
                warn("directory id '" + directory.id + "' is reached twice; not walking "
                        + directory.path + " a second time");
                continue;
            }
            String contentDir = cipher.contentPath(directory.id);
            if (!store.isDirectory(contentDir)) {
                warn("no content directory for " + directory.path + " (expected " + contentDir + ")");
                continue;
            }
            entries.add(new VaultEntry(directory.path, true, contentDir, directory.id, 0, 0));
            String[] names = store.list(contentDir);
            java.util.Arrays.sort(names);
            for (String name : names) {
                readEntry(entries, pending, directory, contentDir, name);
            }
        }

        Collections.sort(entries, new Comparator<VaultEntry>() {
            @Override
            public int compare(VaultEntry a, VaultEntry b) {
                return a.path.compareTo(b.path);
            }
        });
        return entries;
    }

    private void readEntry(List<VaultEntry> entries, Deque<Directory> pending, Directory directory,
                           String contentDir, String name) throws IOException {
        String entryPath = contentDir + "/" + name;

        if (DIRID_FILE.equals(name)) {
            checkDirIdBackup(entryPath, directory);
            return;
        }

        if (name.endsWith(C9R)) {
            String cleartextName = name(directory.id, name);
            if (store.isDirectory(entryPath)) {
                // A subdirectory: the folder is named after the child's encrypted name and holds
                // the child's id in cleartext.
                String treePath = join(directory.path, cleartextName);
                String child = childId(entryPath, treePath);
                if (child != null) {
                    pending.add(new Directory(child, treePath));
                }
            } else {
                long ciphertextSize = store.length(entryPath);
                entries.add(new VaultEntry(join(directory.path, cleartextName), false, entryPath, null,
                        ciphertextSize, VaultCipher.cleartextSize(ciphertextSize)));
            }
            return;
        }

        if (name.endsWith(C9S) && store.isDirectory(entryPath)) {
            // An overlong name: the real encrypted name is inside, and the entry may be a file (with
            // its content beside it) or a directory (with a dir.c9r beside it).
            String realName = readText(entryPath + "/" + NAME_FILE, directory.path);
            if (!realName.endsWith(C9R)) {
                throw new VaultException("shortened entry " + entryPath + " names '" + realName
                        + "', which is not a .c9r entry name");
            }
            String cleartextName = name(directory.id, realName);
            String treePath = join(directory.path, cleartextName);
            if (store.exists(entryPath + "/" + DIR_FILE)) {
                String child = childId(entryPath, treePath);
                if (child != null) {
                    pending.add(new Directory(child, treePath));
                }
            } else if (store.exists(entryPath + "/" + CONTENTS_FILE)) {
                String contentsPath = entryPath + "/" + CONTENTS_FILE;
                long ciphertextSize = store.length(contentsPath);
                entries.add(new VaultEntry(treePath, false, contentsPath, null,
                        ciphertextSize, VaultCipher.cleartextSize(ciphertextSize)));
            } else {
                warn("shortened entry " + entryPath + " holds neither " + DIR_FILE + " nor "
                        + CONTENTS_FILE);
            }
            return;
        }

        warn("unexpected entry in " + contentDir + ": " + name);
    }

    /**
     * Reads a child's id out of a {@code dir.c9r}.
     *
     * @return the id, or null when it is unusable — walking with a bogus id would either find the
     *     root (the empty string) or nothing at all, and reporting the entry as a warning is
     *     honest about what was skipped
     */
    private String childId(String entryPath, String treePath) throws IOException {
        String id = readText(entryPath + "/" + DIR_FILE, treePath);
        if (id.isEmpty() || id.length() > MAX_DIR_ID) {
            warn("directory entry " + treePath + " names the child id '" + id
                    + "', which is not an id");
            return null;
        }
        return id;
    }

    /**
     * The directory id that a subdirectory entry folder names, read from its {@code dir.c9r}.
     *
     * <p>This is the one join in the whole format that is not one-way, and the redirect depends on
     * it entirely: {@code d/XY/…} is named after {@code hashDirectoryId(dirId)}, and the hash cannot
     * be run backwards, so the only way from "the folder the user tapped" to "where that folder's
     * contents live" is to read this file. It is <em>cleartext</em> — 36 bytes of UUID — which is
     * what makes the walk possible at all.
     *
     * <p>The file has to be on local disk before this is called. On the device that means fetching
     * it through the app first ({@code Channel.fetch}): the entry folder holds nothing else, so the
     * app has no reason to have it unless it was asked for.
     *
     * @param vaultRelativeEntryPath the entry folder, relative to the vault root — for example
     *     {@code d/SY/RGEQ…/kymd….c9r}
     */
    public String childDirectoryId(String vaultRelativeEntryPath) throws IOException {
        return childId(vaultRelativeEntryPath, vaultRelativeEntryPath);
    }

    /**
     * Checks {@code dirid.c9r} against the size the content model predicts for the id we already
     * know. It costs nothing and it binds a file that traversal does not otherwise need to the id
     * that traversal does need: if the id we walked with were wrong, this would disagree.
     */
    private void checkDirIdBackup(String path, Directory directory) throws IOException {
        long actual = store.length(path);
        int idBytes = directory.id.getBytes(StandardCharsets.UTF_8).length;
        long expected = VaultCipher.HEADER_BYTES + VaultCipher.CHUNK_OVERHEAD + idBytes;
        if (actual != expected) {
            warn("dirid.c9r of " + directory.path + " is " + actual + " bytes; an id of " + idBytes
                    + " bytes should have made it " + expected);
        }
    }

    private String readText(String path, String context) throws IOException {
        if (!store.exists(path)) {
            throw new VaultException("missing " + path + " (while walking " + context + ")");
        }
        return new String(store.read(path), StandardCharsets.UTF_8).trim();
    }

    private void warn(String message) {
        warnings.add(message);
    }

    private static String strip(String name, String suffix) {
        return name.substring(0, name.length() - suffix.length());
    }

    private static String join(String parentPath, String name) {
        return "/".equals(parentPath) ? name : parentPath + "/" + name;
    }

    /** A directory waiting to be walked: its id, and the cleartext path it is shown at. */
    private static final class Directory {

        final String id;
        final String path;

        Directory(String id, String path) {
            this.id = id;
            this.path = path;
        }
    }
}
