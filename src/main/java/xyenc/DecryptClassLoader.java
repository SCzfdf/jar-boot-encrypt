package xyenc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * 解密类加载器 - 包装 Spring Boot 的 LaunchedClassLoader。
 * <p>
 * 让 Spring Boot 处理嵌套 JAR 的 URL 解析，仅拦截加密类进行解密。
 * 通过读取 META-INF/ENCRYPT-INDEX 确定哪些类被加密。
 */
public class DecryptClassLoader extends ClassLoader {

    private static final String INDEX_PATH = "META-INF/ENCRYPT-INDEX";

    private final ClassLoader delegate;
    private final byte[] key;
    private final byte[] iv;
    private final Set<String> encryptedIndexes;

    static {
        ClassLoader.registerAsParallelCapable();
    }

    public DecryptClassLoader(ClassLoader delegate, byte[] key, byte[] iv) {
        super(delegate);
        this.delegate = delegate;
        this.key = key;
        this.iv = iv;
        this.encryptedIndexes = loadIndexes(delegate);
        System.out.println("[Encrypt] Loaded " + encryptedIndexes.size() + " encrypted entries from " + INDEX_PATH);
    }

    private static Set<String> loadIndexes(ClassLoader classLoader) {
        Set<String> indexes = new HashSet<>();
        try {
            Enumeration<URL> resources = classLoader.getResources(INDEX_PATH);
            while (resources.hasMoreElements()) {
                URL resource = resources.nextElement();
                try (InputStream in = resource.openStream();
                     LineNumberReader lnr = new LineNumberReader(new InputStreamReader(in))) {
                    String name;
                    while ((name = lnr.readLine()) != null) {
                        name = name.trim();
                        if (!name.isEmpty()) {
                            indexes.add(name);
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[Encrypt] Warning: failed to load " + INDEX_PATH + ": " + e.getMessage());
        }
        return indexes;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> c = findLoadedClass(name);
            if (c != null) {
                return c;
            }
            try {
                c = delegate.loadClass(name);
                return c;
            } catch (ClassFormatError e) {
                // Class bytes are encrypted — decrypt and define
                c = decryptAndDefine(name);
                if (resolve) {
                    resolveClass(c);
                }
                return c;
            }
        }
    }

    private Class<?> decryptAndDefine(String name) throws ClassNotFoundException {
        String path = name.replace('.', '/') + ".class";
        URL url = delegate.getResource(path);
        if (url == null) {
            throw new ClassNotFoundException(name);
        }
        try (InputStream in = url.openStream()) {
            byte[] encrypted = CryptoUtils.readAllBytes(in);
            byte[] decrypted = CryptoUtils.decrypt(key, iv, encrypted);
            return defineClass(name, decrypted, 0, decrypted.length);
        } catch (ClassNotFoundException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ClassNotFoundException(name, ex);
        }
    }

    @Override
    public URL getResource(String name) {
        return delegate.getResource(name);
    }

    @Override
    public Enumeration<URL> getResources(String name) throws java.io.IOException {
        return delegate.getResources(name);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        InputStream raw = delegate.getResourceAsStream(name);
        if (raw == null) {
            return null;
        }
        // 根据 ENCRYPT-INDEX 判断是否需要解密
        if (encryptedIndexes.contains(name)) {
            try {
                byte[] bytes = CryptoUtils.readAllBytes(raw);
                raw.close();
                // Check if bytes are encrypted (not a valid class file)
                // Java class files start with magic number 0xCAFEBABE
                if (bytes.length >= 4 && !(bytes[0] == (byte) 0xCA && bytes[1] == (byte) 0xFE
                        && bytes[2] == (byte) 0xBA && bytes[3] == (byte) 0xBE)) {
                    byte[] decrypted = CryptoUtils.decrypt(key, iv, bytes);
                    return new ByteArrayInputStream(decrypted);
                }
                return new ByteArrayInputStream(bytes);
            } catch (Exception e) {
                System.err.println("[Encrypt] Warning: failed to decrypt resource " + name + ": " + e.getMessage());
                return null;
            }
        }
        return raw;
    }
}
