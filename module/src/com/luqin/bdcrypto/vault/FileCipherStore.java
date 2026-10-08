package com.luqin.bdcrypto.vault;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A {@link CipherStore} over a local directory — the whole vault as it sits on disk.
 *
 * <p>This is what the offline harness uses, and it is also what the module will use whenever the
 * ciphertext has already landed locally: {@code /storage/emulated/0/Download/BaiduNetdisk/<cloud
 * path>} is a real directory on the device, so the same walk runs there unchanged.
 *
 * <p>Everything is {@code java.io.File}: no {@code java.nio.file}, which is why this class compiles
 * against android.jar and against a bare JDK alike.
 */
public final class FileCipherStore implements CipherStore {

    private final File root;

    public FileCipherStore(File root) {
        this.root = root;
    }

    public File root() {
        return root;
    }

    private File resolve(String path) {
        File f = root;
        int start = 0;
        for (int i = 0; i <= path.length(); i++) {
            if (i == path.length() || path.charAt(i) == '/') {
                if (i > start) {
                    f = new File(f, path.substring(start, i));
                }
                start = i + 1;
            }
        }
        return f;
    }

    @Override
    public boolean exists(String path) {
        return resolve(path).exists();
    }

    @Override
    public boolean isDirectory(String path) {
        return resolve(path).isDirectory();
    }

    @Override
    public String[] list(String path) {
        String[] names = resolve(path).list();
        return names == null ? new String[0] : names;
    }

    @Override
    public byte[] read(String path) throws IOException {
        File f = resolve(path);
        if (!f.isFile()) {
            throw new VaultException("not a file: " + path);
        }
        InputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(f.length(), 1 << 20));
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    @Override
    public long length(String path) {
        return resolve(path).length();
    }
}
