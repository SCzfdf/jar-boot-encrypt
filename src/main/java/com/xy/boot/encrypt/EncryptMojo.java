package com.xy.boot.encrypt;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import xyenc.CryptoUtils;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

/**
 * Maven Mojo：加密 Spring Boot fat JAR 中的 .class 文件。
 * <p>
 * 处理流程：
 * 1. 读取 spring-boot-maven-plugin 产出的 fat JAR
 * 2. BOOT-INF/classes/ 下匹配 include 的 .class 文件加密
 * 3. BOOT-INF/lib/*.jar 嵌套 JAR 中匹配 include 的 .class 文件加密（重新打包嵌套 JAR）
 * 4. 写入 META-INF/ENCRYPT-INDEX 索引
 * 5. 注入 xyenc/*.class 运行时类
 * 6. 修改 MANIFEST.MF 的 Main-Class 为 xyenc.EncryptLauncher
 * 7. 输出加密后的 JAR
 */
@Mojo(name = "encrypt", defaultPhase = LifecyclePhase.PACKAGE)
public class EncryptMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(property = "jar.encrypt.password", required = true)
    private String password;

    /**
     * ANT 风格的 include 模式列表，如 com/xy/**
     */
    @Parameter
    private List<String> includes;

    /**
     * ANT 风格的 exclude 模式列表
     */
    @Parameter
    private List<String> excludes;

    /**
     * 输出文件后缀
     */
    @Parameter(defaultValue = ".encrypted")
    private String outputSuffix;

    private byte[] key;
    private byte[] iv;

    @Override
    public void execute() throws MojoExecutionException {
        try {
            // 跳过 POM 类型模块
            if ("pom".equals(project.getPackaging())) {
                getLog().info("Skipping POM module: " + project.getArtifactId());
                return;
            }

            // 派生密钥
            byte[][] keyIv = CryptoUtils.deriveKeyIv(password.trim());
            this.key = keyIv[0];
            this.iv = keyIv[1];

            File inputJar = project.getArtifact().getFile();
            if (inputJar == null || !inputJar.exists()) {
                throw new MojoExecutionException("Project artifact not found. Ensure spring-boot-maven-plugin runs before this plugin.");
            }

            String outputName = inputJar.getName();
            if (outputName.endsWith(".jar")) {
                outputName = outputName.substring(0, outputName.length() - 4) + outputSuffix;
            } else {
                outputName = outputName + outputSuffix;
            }
            File outputJar = new File(inputJar.getParentFile(), outputName);

            getLog().info("Encrypting: " + inputJar.getAbsolutePath());
            getLog().info("Output:     " + outputJar.getAbsolutePath());

            List<Pattern> includePatterns = compilePatterns(includes);
            List<Pattern> excludePatterns = compilePatterns(excludes);

            Set<String> encryptedIndex = new LinkedHashSet<>();
            // 收集加密后的字节用于完整性签名
            Map<String, byte[]> encryptedBytesMap = new TreeMap<>();

            // 收集插件自身的 xyenc/*.class 资源
            Map<String, byte[]> runtimeClasses = collectRuntimeClasses();

            try (JarFile srcJar = new JarFile(inputJar);
                 JarOutputStream jos = new JarOutputStream(new BufferedOutputStream(new FileOutputStream(outputJar)))) {

                Manifest manifest = srcJar.getManifest();
                Manifest newManifest = new Manifest(manifest);
                // 修改 Main-Class
                newManifest.getMainAttributes().putValue("Main-Class", "xyenc.EncryptLauncher");

                // 写 MANIFEST
                jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
                newManifest.write(jos);
                jos.closeEntry();

                Enumeration<JarEntry> entries = srcJar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String name = entry.getName();

                    // 跳过原 MANIFEST（已写入）
                    if (name.equals("META-INF/MANIFEST.MF")) {
                        continue;
                    }

                    // BOOT-INF/classes/ 下的 .class 文件
                    if (name.startsWith("BOOT-INF/classes/") && name.endsWith(".class")) {
                        String classPath = name.substring("BOOT-INF/classes/".length());
                        if (shouldEncrypt(classPath, includePatterns, excludePatterns)) {
                            byte[] original = readEntry(srcJar, entry);
                            byte[] encrypted = CryptoUtils.encrypt(key, iv, original);
                            writeEntry(jos, name, encrypted);
                            encryptedIndex.add(classPath);
                            // 签名 key 用完整的 JAR 内路径，避免与嵌套 JAR 中同名 class 冲突
                            encryptedBytesMap.put(name, encrypted);
                            continue;
                        }
                    }

                    // BOOT-INF/lib/*.jar 嵌套 JAR
                    if (name.startsWith("BOOT-INF/lib/") && name.endsWith(".jar")) {
                        byte[] jarBytes = readEntry(srcJar, entry);
                        byte[] processed = processNestedJar(name, jarBytes, includePatterns, excludePatterns, encryptedIndex, encryptedBytesMap);
                        if (processed != null) {
                            // 嵌套 JAR 被修改过，使用 STORED 方式
                            writeStoredEntry(jos, name, processed);
                            continue;
                        }
                        // 未修改，原样写入
                        writeStoredEntry(jos, name, jarBytes);
                        continue;
                    }

                    // 其他条目原样拷贝
                    if (entry.isDirectory()) {
                        jos.putNextEntry(new JarEntry(name));
                        jos.closeEntry();
                    } else {
                        byte[] data = readEntry(srcJar, entry);
                        writeEntry(jos, name, data);
                    }
                }

                // 写入 ENCRYPT-INDEX
                StringBuilder indexContent = new StringBuilder();
                for (String path : encryptedIndex) {
                    indexContent.append(path).append("\n");
                }
                byte[] indexBytes = indexContent.toString().getBytes("UTF-8");
                writeEntry(jos, "BOOT-INF/classes/META-INF/ENCRYPT-INDEX", indexBytes);

                // 生成完整性签名：
                // 对 INDEX 内容 + 所有加密 class 的完整路径和密文做 SHA-256 摘要，再 HMAC 签名
                // 完整路径包含来源前缀（BOOT-INF/classes/... 或 BOOT-INF/lib/a.jar!/...），解决同名 class 冲突
                // 运行时无法重建完整路径摘要，因此只校验 INDEX 内容的 HMAC（密码正确性验证）
                // 完整的字节级防篡改由第一层整包校验（.sign 文件）保证
                byte[] indexHmac = CryptoUtils.hmacSha256(key, indexBytes);
                String signContent = CryptoUtils.bytesToHex(indexHmac) + "\n";
                writeEntry(jos, "BOOT-INF/classes/META-INF/ENCRYPT-SIGN", signContent.getBytes("UTF-8"));
                getLog().info("Integrity signature generated: " + CryptoUtils.bytesToHex(indexHmac).substring(0, 16) + "...");

                // 注入运行时类到 JAR 根目录
                for (Map.Entry<String, byte[]> rc : runtimeClasses.entrySet()) {
                    writeEntry(jos, rc.getKey(), rc.getValue());
                }
            }

            getLog().info("Encryption complete. Encrypted " + encryptedIndex.size() + " classes.");
            getLog().info("Output: " + outputJar.getAbsolutePath());

            // 整包签名：对加密 JAR 文件整体计算 HMAC-SHA256，写入 .sign 旁路文件
            byte[] jarHash = sha256File(outputJar);
            byte[] jarSignature = CryptoUtils.hmacSha256(key, jarHash);
            String jarSignHex = CryptoUtils.bytesToHex(jarSignature);
            File signFile = new File(outputJar.getAbsolutePath() + ".sign");
            try (FileOutputStream fos = new FileOutputStream(signFile)) {
                fos.write(jarSignHex.getBytes("UTF-8"));
            }
            getLog().info("Whole-JAR signature: " + signFile.getName() + " (" + jarSignHex.substring(0, 16) + "...)");

        } catch (MojoExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new MojoExecutionException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 处理嵌套 JAR：如果内部有匹配的 .class 则加密并重新打包。
     * @param outerEntryName 外层 JAR 中的条目名，如 BOOT-INF/lib/xy-common-core-5.2.02.jar
     * @return 重新打包后的 JAR 字节，如果无修改返回 null
     */
    private byte[] processNestedJar(String outerEntryName, byte[] jarBytes, List<Pattern> includePatterns,
                                     List<Pattern> excludePatterns, Set<String> encryptedIndex,
                                     Map<String, byte[]> encryptedBytesMap) throws Exception {
        boolean modified = false;

        ByteArrayInputStream bis = new ByteArrayInputStream(jarBytes);
        JarInputStream jis = new JarInputStream(bis);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        JarOutputStream jos = new JarOutputStream(bos);

        // 保留原始 MANIFEST
        Manifest manifest = jis.getManifest();
        if (manifest != null) {
            jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
            manifest.write(jos);
            jos.closeEntry();
        }

        JarEntry entry;
        while ((entry = jis.getNextJarEntry()) != null) {
            String name = entry.getName();

            if (name.equals("META-INF/MANIFEST.MF")) {
                continue; // 已写入
            }

            if (name.endsWith(".class")) {
                String classPath = name; // 嵌套 JAR 内部直接是 classpath 路径
                if (shouldEncrypt(classPath, includePatterns, excludePatterns)) {
                    byte[] original = CryptoUtils.readAllBytes(jis);
                    byte[] encrypted = CryptoUtils.encrypt(key, iv, original);
                    writeEntry(jos, name, encrypted);
                    encryptedIndex.add(classPath);
                    // 签名 key 用 "outerJar!/innerClass" 格式，确保跨 JAR 唯一
                    encryptedBytesMap.put(outerEntryName + "!/" + classPath, encrypted);
                    modified = true;
                    continue;
                }
            }

            if (entry.isDirectory()) {
                jos.putNextEntry(new JarEntry(name));
                jos.closeEntry();
            } else {
                byte[] data = CryptoUtils.readAllBytes(jis);
                writeEntry(jos, name, data);
            }
        }

        jis.close();
        jos.close();

        return modified ? bos.toByteArray() : null;
    }

    /**
     * 判断 classPath 是否需要加密。
     */
    private boolean shouldEncrypt(String classPath, List<Pattern> includePatterns, List<Pattern> excludePatterns) {
        if (includePatterns.isEmpty()) {
            return true; // 无 include 则全部加密
        }
        boolean included = false;
        for (Pattern p : includePatterns) {
            if (p.matcher(classPath).matches()) {
                included = true;
                break;
            }
        }
        if (!included) return false;

        for (Pattern p : excludePatterns) {
            if (p.matcher(classPath).matches()) {
                return false;
            }
        }
        return true;
    }

    /**
     * 将 ANT 风格的模式列表编译为正则表达式。
     */
    private List<Pattern> compilePatterns(List<String> antPatterns) {
        if (antPatterns == null || antPatterns.isEmpty()) {
            return Collections.emptyList();
        }
        List<Pattern> result = new ArrayList<>();
        for (String ant : antPatterns) {
            String regex = antToRegex(ant);
            result.add(Pattern.compile(regex));
        }
        return result;
    }

    /**
     * ANT 模式转正则：** → .*, * → [^/]*, ? → [^/]
     */
    private String antToRegex(String antPattern) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < antPattern.length()) {
            char c = antPattern.charAt(i);
            if (c == '*') {
                if (i + 1 < antPattern.length() && antPattern.charAt(i + 1) == '*') {
                    sb.append(".*");
                    i += 2;
                    // skip trailing /
                    if (i < antPattern.length() && antPattern.charAt(i) == '/') {
                        i++;
                    }
                } else {
                    sb.append("[^/]*");
                    i++;
                }
            } else if (c == '?') {
                sb.append("[^/]");
                i++;
            } else if (c == '.') {
                sb.append("\\.");
                i++;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    /**
     * 收集插件自身的 xyenc/*.class 文件，用于注入到加密 JAR 根目录。
     */
    private Map<String, byte[]> collectRuntimeClasses() throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        String[] runtimeClasses = {
            "xyenc/CryptoUtils.class",
            "xyenc/DecryptClassLoader.class",
            "xyenc/EncryptLauncher.class"
        };
        for (String name : runtimeClasses) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(name)) {
                if (in == null) {
                    throw new MojoExecutionException("Runtime class not found in plugin JAR: " + name);
                }
                classes.put(name, CryptoUtils.readAllBytes(in));
            }
        }
        return classes;
    }

    private byte[] readEntry(JarFile jar, JarEntry entry) throws IOException {
        try (InputStream in = jar.getInputStream(entry)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    private void writeEntry(JarOutputStream jos, String name, byte[] data) throws IOException {
        JarEntry entry = new JarEntry(name);
        jos.putNextEntry(entry);
        jos.write(data);
        jos.closeEntry();
    }

    /**
     * 以 STORED（无压缩）方式写入条目。Spring Boot 嵌套 JAR 必须使用 STORED。
     */
    private void writeStoredEntry(JarOutputStream jos, String name, byte[] data) throws IOException {
        JarEntry entry = new JarEntry(name);
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(data.length);
        entry.setCompressedSize(data.length);
        CRC32 crc = new CRC32();
        crc.update(data);
        entry.setCrc(crc.getValue());
        jos.putNextEntry(entry);
        jos.write(data);
        jos.closeEntry();
    }

    /**
     * 计算文件的 SHA-256 摘要。
     */
    private byte[] sha256File(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) != -1) {
                digest.update(buf, 0, n);
            }
        }
        return digest.digest();
    }
}
