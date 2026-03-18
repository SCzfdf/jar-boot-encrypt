# jar-boot-encrypt - Spring Boot JAR 加密 Maven 插件

## 概述

自定义的轻量级 Spring Boot JAR 加密插件，替代 XJar。通过 AES 加密 .class 文件防止反编译，运行时通过自定义 ClassLoader 透明解密。

- **加密算法**: AES/CBC/PKCS5Padding
- **密钥派生**: SHA-256(password) → 前16字节=AES Key, 后16字节=IV
- **兼容版本**: Spring Boot 3.2+ (使用 `jar:nested:` 协议)
- **部署方式**: 兼容 PropertiesLauncher + 外部 lib 目录

## 项目结构

```
jar-boot-encrypt/
├── pom.xml                                          # Maven 插件项目配置
└── src/main/java/
    ├── xyenc/                                       # 运行时类 (会被注入到加密 JAR 中)
    │   ├── CryptoUtils.java                         # AES 加解密 + SHA-256 密钥派生
    │   ├── DecryptClassLoader.java                  # 解密类加载器 (包装 LaunchedClassLoader)
    │   └── EncryptLauncher.java                     # 启动器 (替换原始 Main-Class)
    └── com/xy/boot/encrypt/
        └── EncryptMojo.java                         # Maven 插件 Mojo (构建时加密)
```

## 各文件作用

### `xyenc/CryptoUtils.java` - 加解密工具

纯 JDK 实现，无外部依赖。提供：
- `deriveKeyIv(password)`: 密码 → SHA-256 → AES Key(16B) + IV(16B)
- `encrypt(key, iv, data)` / `decrypt(key, iv, data)`: AES/CBC 加解密
- `readAllBytes(InputStream)`: 流读取工具

### `xyenc/DecryptClassLoader.java` - 解密类加载器

**核心机制 - Wrapper 模式**：包装 Spring Boot 的 `LaunchedClassLoader`，而不是替换它。

工作流程：
1. 构造时从 `META-INF/ENCRYPT-INDEX` 读取所有加密类路径列表
2. `loadClass()`: 先委托给 delegate (LaunchedClassLoader) 加载
   - 加载成功 → 直接返回（未加密的类）
   - 抛出 `ClassFormatError` → 说明字节是加密的 → 调用 `decryptAndDefine()`
3. `getResourceAsStream()`: 根据 ENCRYPT-INDEX 判断是否需要解密，供 Spring 组件扫描使用
4. CAFEBABE 魔数检测：额外校验，防止误解密未加密的 class 文件

**为什么不会有 A!=A 问题**：加密类只能通过 DecryptClassLoader 定义（delegate 会抛 ClassFormatError），形成天然隔离。

### `xyenc/EncryptLauncher.java` - 加密 JAR 启动器

- 继承 `PropertiesLauncher`（支持 `-Dloader.path` 外部依赖加载）
- 密码来源：`-Djar.encrypt.password=xxx` 系统属性，或 stdin 交互输入
- 重写 `createClassLoader()`：用 `DecryptClassLoader` 包装原始 ClassLoader

### `com/xy/boot/encrypt/EncryptMojo.java` - Maven 插件

构建时执行，处理流程：
1. 跳过 POM 类型模块
2. 读取 spring-boot-maven-plugin 产出的 fat JAR
3. 加密 `BOOT-INF/classes/` 下匹配 include 模式的 .class 文件
4. 加密 `BOOT-INF/lib/*.jar` 嵌套 JAR 中匹配的 .class 文件（重新打包）
5. 生成 `META-INF/ENCRYPT-INDEX` 索引（列出所有加密类路径）
6. 注入 `xyenc/*.class` 运行时类到 JAR 根目录
7. 修改 `MANIFEST.MF` 的 `Main-Class` 为 `xyenc.EncryptLauncher`
8. 输出 `.encrypted` 文件

插件参数：
| 参数 | 说明 | 示例 |
|------|------|------|
| `password` | 加密密码（必填） | `${jar.encrypt.password}` |
| `includes` | ANT 风格包含模式 | `com/xy/**` |
| `excludes` | ANT 风格排除模式 | `static/**` |
| `outputSuffix` | 输出文件后缀（默认 `.encrypted`） | `.encrypted` |

## 构建插件

```bash
cd D:\project\jar-boot-encrypt
mvn clean install
```

## 加密后的 JAR 内部结构

```
xy-auth.encrypted
├── META-INF/MANIFEST.MF              # Main-Class: xyenc.EncryptLauncher
├── xyenc/
│   ├── CryptoUtils.class              # 注入的运行时类
│   ├── DecryptClassLoader.class       # 注入的运行时类
│   └── EncryptLauncher.class          # 注入的运行时类
├── org/springframework/boot/loader/   # Spring Boot Loader (原样保留)
├── BOOT-INF/
│   ├── classes/
│   │   ├── META-INF/ENCRYPT-INDEX     # 加密类索引文件
│   │   └── com/xy/**/*.class          # 已加密的 class 文件
│   ├── lib/
│   │   ├── xy-common-core-5.2.02.jar  # 嵌套 JAR (内部 com/xy/** 也已加密)
│   │   └── ...
│   └── classpath.idx
```

## 运行时解密流程

```
JVM 启动
  └→ EncryptLauncher.main()
       ├→ 读取密码 (-Djar.encrypt.password 或 stdin)
       ├→ SHA-256 派生 AES Key + IV
       └→ launch(args)
            └→ createClassLoader()
                 ├→ super.createClassLoader() → LaunchedClassLoader (处理 jar:nested: URL)
                 └→ new DecryptClassLoader(parent, key, iv)
                      └→ 读取 META-INF/ENCRYPT-INDEX
                           └→ 应用启动，透明解密
```
