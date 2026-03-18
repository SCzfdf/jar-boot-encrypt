package xyenc;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * AES/CBC/PKCS5Padding 加密解密工具。
 * 密钥派生：SHA-256(password) → 前16字节=AES key，后16字节=IV。
 */
public final class CryptoUtils {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int BUFFER_SIZE = 8192;

    private CryptoUtils() {}

    /**
     * 从密码派生 AES key (16 bytes) 和 IV (16 bytes)。
     * @return [0]=key, [1]=iv
     */
    public static byte[][] deriveKeyIv(String password) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(password.getBytes("UTF-8"));
        byte[] key = Arrays.copyOfRange(hash, 0, 16);
        byte[] iv = Arrays.copyOfRange(hash, 16, 32);
        return new byte[][] { key, iv };
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static void encrypt(byte[] key, byte[] iv, InputStream in, OutputStream out) throws Exception {
        byte[] data = readAllBytes(in);
        out.write(encrypt(key, iv, data));
    }

    public static void decrypt(byte[] key, byte[] iv, InputStream in, OutputStream out) throws Exception {
        byte[] data = readAllBytes(in);
        out.write(decrypt(key, iv, data));
    }

    public static byte[] readAllBytes(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[BUFFER_SIZE];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
