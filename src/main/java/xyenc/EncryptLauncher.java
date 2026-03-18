package xyenc;

import org.springframework.boot.loader.launch.PropertiesLauncher;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Collection;

/**
 * 加密 JAR 启动器。extends PropertiesLauncher 以支持 -Dloader.path 外部依赖加载。
 * <p>
 * 密码来源（优先级）：
 * 1. -Djar.encrypt.password=xxx 系统属性
 * 2. stdin 单行输入
 */
public class EncryptLauncher extends PropertiesLauncher {

    private static byte[] KEY;
    private static byte[] IV;

    public EncryptLauncher() throws Exception {
        super();
    }

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("jar.encrypt.password");
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

        byte[][] keyIv = CryptoUtils.deriveKeyIv(password);
        KEY = keyIv[0];
        IV = keyIv[1];

        System.out.println("[Encrypt] Password accepted, starting application...");
        new EncryptLauncher().launch(args);
    }

    @Override
    protected ClassLoader createClassLoader(Collection<URL> urls) throws Exception {
        ClassLoader parent = super.createClassLoader(urls);
        return new DecryptClassLoader(parent, KEY, IV);
    }
}
