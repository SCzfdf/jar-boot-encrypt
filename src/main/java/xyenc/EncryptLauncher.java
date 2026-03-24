package xyenc;

import org.springframework.boot.loader.launch.PropertiesLauncher;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Collection;

/**
 * 加密 JAR 启动器。extends PropertiesLauncher 以支持 -Dloader.path 外部依赖加载。
 * <p>
 * 密码来源（优先级）：
 * 1. -Djar.encrypt.password=xxx 系统属性
 * 2. stdin 单行输入
 * <p>
 * 启动时执行完整性校验：读取 META-INF/ENCRYPT-SIGN，重新计算 HMAC 与之比对。
 * 校验失败则拒绝启动，防止加密 class 被篡改。
 */
public class EncryptLauncher extends PropertiesLauncher {

    private static byte[] KEY;
    private static byte[] IV;

    public EncryptLauncher() throws Exception {
        super();
    }

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("jar.encrypt.password");
        String jarSign = System.getProperty("jar.encrypt.sign");
        if (password == null || password.trim().isEmpty()) {
            System.out.print("Enter encryption password: ");
            System.out.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            password = reader.readLine();
        }
        if (password == null || password.trim().isEmpty()) {
            System.err.println("[Encrypt] Error: No password provided. Use -Djar.encrypt.password=xxx or stdin.");
            System.exit(1);
        }
        password = password.trim();


        if (jarSign == null || jarSign.trim().isEmpty()) {
            System.out.print("Enter encryption jarSign: ");
            System.out.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            jarSign = reader.readLine();
        }
        if (jarSign == null || jarSign.trim().isEmpty()) {
            System.err.println("[Encrypt] Error: No password provided. Use -Djar.encrypt.password=xxx or stdin.");
            System.exit(1);
        }
        jarSign = jarSign.trim();

        byte[][] keyIv = CryptoUtils.deriveKeyIv(password);
        KEY = keyIv[0];
        IV = keyIv[1];

        System.out.println("[Encrypt] Password accepted, starting application...");

        // 整包校验：在 launch 之前校验 JAR 文件本身
        verifyJarFile(jarSign);

        new EncryptLauncher().launch(args);
    }

    @Override
    protected ClassLoader createClassLoader(Collection<URL> urls) throws Exception {
        ClassLoader parent = super.createClassLoader(urls);
        verifyIntegrity(parent);
        return new DecryptClassLoader(parent, KEY, IV);
    }

    /**
     * 加密类索引校验（第二层）。
     * 对 META-INF/ENCRYPT-INDEX 内容计算 HMAC-SHA256，与 META-INF/ENCRYPT-SIGN 比对。
     * 验证：1) 密码正确  2) INDEX 未被篡改（加密类列表完整）
     * 完整的字节级防篡改由第一层整包校验（.sign 文件）保证。
     */
    private static void verifyIntegrity(ClassLoader cl) throws Exception {
        // 读取签名
        InputStream signStream = cl.getResourceAsStream("META-INF/ENCRYPT-SIGN");
        if (signStream == null) {
            System.out.println("[Encrypt] No integrity signature found (META-INF/ENCRYPT-SIGN), skipping verification.");
            return;
        }
        String expectedHex;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(signStream))) {
            expectedHex = br.readLine();
        }
        if (expectedHex == null || expectedHex.trim().isEmpty()) {
            System.err.println("[Encrypt] FATAL: Integrity signature file is empty!");
            System.exit(1);
        }
        expectedHex = expectedHex.trim();

        // 读取加密索引原始字节
        InputStream indexStream = cl.getResourceAsStream("META-INF/ENCRYPT-INDEX");
        if (indexStream == null) {
            System.err.println("[Encrypt] FATAL: ENCRYPT-INDEX not found but ENCRYPT-SIGN exists. JAR may be corrupted!");
            System.exit(1);
        }
        byte[] indexBytes = CryptoUtils.readAllBytes(indexStream);
        indexStream.close();

        // 计算 INDEX 内容的 HMAC
        byte[] actualHmac = CryptoUtils.hmacSha256(KEY, indexBytes);
        String actualHex = CryptoUtils.bytesToHex(actualHmac);

        if (!actualHex.equals(expectedHex)) {
            System.err.println("[Encrypt] FATAL: Integrity check FAILED!");
            System.err.println("[Encrypt] Possible causes: wrong password, or ENCRYPT-INDEX has been tampered with.");
            System.exit(1);
        }

        // 统计条目数
        int count = 0;
        for (byte b : indexBytes) {
            if (b == '\n') count++;
        }
        System.out.println("[Encrypt] Integrity check PASSED (" + count + " encrypted entries verified).");
    }

    /**
     * 整包校验：对 JAR 文件整体计算 SHA-256 → HMAC-SHA256，与 .sign 旁路文件比对。
     * 检测任何对 JAR 文件的修改（包括非加密资源、MANIFEST、注入的运行时类等）。
     */
    private static void verifyJarFile(String jarSign) {
        try {
            // 从 code source 获取 JAR 文件路径
            URL codeSource = EncryptLauncher.class.getProtectionDomain().getCodeSource().getLocation();
            File jarFile = new File(codeSource.toURI());
            System.out.println("==========" + codeSource.toURI());
            if (!jarFile.isFile()) {
                System.out.println("[Encrypt] Not running from JAR file, skipping whole-JAR verification.");
                return;
            }

//            File signFile = new File(jarFile.getAbsolutePath() + ".sign");
//            if (!signFile.exists()) {
//                System.out.println("[Encrypt] No .sign file found (" + signFile.getName() + "), skipping whole-JAR verification.");
//                return;
//            }

            // 读取期望签名
//            String expectedHex;
//            try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(signFile)))) {
//                expectedHex = br.readLine();
//            }
//            if (expectedHex == null || expectedHex.trim().isEmpty()) {
//                System.err.println("[Encrypt] FATAL: .sign file is empty!");
//                System.exit(1);
//            }
//            expectedHex = expectedHex.trim();

            // 计算 JAR 文件 SHA-256
            System.out.println("[Encrypt] Verifying whole-JAR integrity (" + jarFile.getName() + ")...");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(jarFile)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = fis.read(buf)) != -1) {
                    digest.update(buf, 0, n);
                }
            }
            byte[] jarHash = digest.digest();
            byte[] actualSignature = CryptoUtils.hmacSha256(KEY, jarHash);
            String actualHex = CryptoUtils.bytesToHex(actualSignature);

            if (!actualHex.equals(jarSign)) {
                System.err.println("[Encrypt] FATAL: Whole-JAR integrity check FAILED!");
                System.err.println("[Encrypt] Expected: " + jarSign.substring(0, 16) + "...");
                System.err.println("[Encrypt] Actual:   " + actualHex.substring(0, 16) + "...");
                System.err.println("[Encrypt] JAR file may have been tampered with. Refusing to start.");
                System.exit(1);
            }

            System.out.println("[Encrypt] Whole-JAR integrity check PASSED.");
        } catch (Exception e) {
            System.err.println("[Encrypt] FATAL: Whole-JAR verification error: " + e.getMessage());
            System.exit(1);
        }
    }
}
