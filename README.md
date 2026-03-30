# jar-boot-encrypt - Spring Boot JAR 加密 Maven 插件

## 概述

自定义的轻量级 Spring Boot JAR 加密插件，替代 XJar。通过 AES 加密 .class 文件防止反编译，运行时通过自定义 ClassLoader 透明解密。

- **加密算法**: AES/CBC/PKCS5Padding
- **密钥派生**: SHA-256(password) → 前16字节=AES Key, 后16字节=IV
- **完整性校验**: HMAC-SHA256 签名，启动时校验防篡改
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
- `hmacSha256(key, data)`: HMAC-SHA256 签名，用于完整性校验
- `bytesToHex(bytes)` / `hexToBytes(hex)`: 十六进制编解码
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
- 密码/签名来源（优先级从高到低）：
  1. `-Djar.encrypt.password=xxx` / `-Djar.encrypt.sign=xxx` 系统属性
  2. 命令行参数：`java -jar app.jar <password> <jarSign>`
  3. jarSign 可从 JAR 同级目录的 `.sign` 文件自动读取
  4. stdin 交互输入（兜底）
- 重写 `createClassLoader()`：用 `DecryptClassLoader` 包装原始 ClassLoader
- **启动时完整性校验**：读取 `META-INF/ENCRYPT-SIGN`，重新计算所有加密 class 的 HMAC-SHA256 并比对，不一致则拒绝启动

### `com/xy/boot/encrypt/EncryptMojo.java` - Maven 插件

构建时执行，处理流程：
1. 跳过 POM 类型模块
2. 读取 spring-boot-maven-plugin 产出的 fat JAR
3. 加密 `BOOT-INF/classes/` 下匹配 include 模式的 .class 文件
4. 加密 `BOOT-INF/lib/*.jar` 嵌套 JAR 中匹配的 .class 文件（重新打包）
5. 生成 `META-INF/ENCRYPT-INDEX` 索引（列出所有加密类路径）
6. 生成 `META-INF/ENCRYPT-SIGN` 完整性签名（HMAC-SHA256）
7. 注入 `xyenc/*.class` 运行时类到 JAR 根目录
8. 修改 `MANIFEST.MF` 的 `Main-Class` 为 `xyenc.EncryptLauncher`
9. 输出 `.encrypted` 文件

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
│   │   ├── META-INF/ENCRYPT-SIGN      # HMAC-SHA256 完整性签名
│   │   └── com/xy/**/*.class          # 已加密的 class 文件
│   ├── lib/
│   │   ├── xy-common-core-5.2.02.jar  # 嵌套 JAR (内部 com/xy/** 也已加密)
│   │   └── ...
│   └── classpath.idx
```

构建后同时生成旁路签名文件：
```
target/
├── xy-auth.encrypted           # 加密后的 JAR
└── xy-auth.encrypted.sign      # 整包 HMAC-SHA256 签名（部署时必须一起分发）
```

## 运行时解密流程

```
JVM 启动
  └→ EncryptLauncher.main(args)
       ├→ 读取密码 (优先级: -D属性 > args[0] > stdin)
       ├→ 读取jarSign (优先级: -D属性 > args[1] > .sign文件 > stdin)
       ├→ SHA-256 派生 AES Key + IV
       ├→ verifyJarFile()  ← 第一层：整包校验
       │    ├→ 从 code source 获取 JAR 文件路径
       │    ├→ 读取 .sign 旁路文件 (期望签名)
       │    ├→ SHA-256(整个JAR文件) → HMAC-SHA256(key, hash)
       │    ├→ 比对: 匹配 → PASSED ✓
       │    └→ 比对: 不匹配 → FAILED ✗ → System.exit(1)
       └→ launch(args)
            └→ createClassLoader()
                 ├→ super.createClassLoader() → LaunchedClassLoader
                 ├→ verifyIntegrity()  ← 第二层：INDEX + 密码校验
                 │    ├→ 读取 META-INF/ENCRYPT-SIGN (期望签名)
                 │    ├→ 读取 META-INF/ENCRYPT-INDEX (原始字节)
                 │    ├→ HMAC-SHA256(key, INDEX字节) → 实际签名
                 │    ├→ 比对: 匹配 → PASSED ✓ (密码正确 + INDEX 未篡改)
                 │    └→ 比对: 不匹配 → FAILED ✗ → System.exit(1)
                 └→ new DecryptClassLoader(parent, key, iv)
                      └→ 读取 META-INF/ENCRYPT-INDEX
                           └→ 应用启动，透明解密
```

## 双层完整性校验机制

### 第一层：整包校验（verifyJarFile）

在 `launch()` 之前执行，校验 JAR 文件本身是否被修改。

**签名生成**（构建时）：
1. 加密 JAR 写入完成后，计算整个文件的 `SHA-256`
2. `HMAC-SHA256(AES_Key, SHA-256)` → 64 字符十六进制签名
3. 写入 `<jarname>.sign` 旁路文件（与 JAR 同目录）

**签名校验**（启动时）：
1. 从 `ProtectionDomain.getCodeSource()` 获取 JAR 文件路径
2. 读取同名 `.sign` 文件
3. 重新计算整个 JAR 文件的 HMAC，与 `.sign` 比对
4. 不匹配则 `System.exit(1)`

### 第二层：INDEX 签名校验（verifyIntegrity）

在 `createClassLoader()` 中执行，校验加密索引未被篡改 + 密码正确性。

**签名生成**（构建时）：
1. 生成 `META-INF/ENCRYPT-INDEX` 的完整内容字节
2. `HMAC-SHA256(AES_Key, INDEX字节)` → 写入 `META-INF/ENCRYPT-SIGN`

**签名校验**（启动时）：
1. 读取 `META-INF/ENCRYPT-INDEX` 原始字节
2. 读取 `META-INF/ENCRYPT-SIGN` 中的期望签名
3. 重新计算 `HMAC-SHA256(AES_Key, INDEX字节)` 比对
4. 不匹配则 `System.exit(1)`

> 注：字节级防篡改由第一层整包校验全面覆盖。第二层作为纵深防御，确保即使 `.sign` 旁路文件丢失，错误密码或 INDEX 篡改仍会被拦截。

### 重复 class 路径处理

当多个嵌套 JAR 包含相同全路径的 class 时（如 `lib/a.jar` 和 `lib/b.jar` 都含 `com/xy/Foo.class`）：
- **加密**：两个 JAR 内的 class 各自独立加密，互不影响
- **INDEX**：使用 `Set<String>`，classpath 路径只记录一条（去重）
- **签名**：构建时使用完整来源路径（`BOOT-INF/lib/a.jar!/com/xy/Foo.class`）作为签名 key，确保不会因重复而丢失
- **运行时**：ClassLoader 按 classpath 顺序加载第一个匹配的 class，与标准 Java 行为一致

### 防御能力

| 篡改类型 | 第一层（整包） | 第二层（INDEX） |
|----------|:---:|:---:|
| 修改已加密 class 字节 | 能检测 | — |
| 删除已加密 class 文件 | 能检测 | — |
| 修改 ENCRYPT-INDEX | 能检测 | 能检测 |
| 添加/删除加密类条目 | 能检测 | 能检测 |
| 修改非加密资源/配置 | 能检测 | — |
| 修改 MANIFEST.MF | 能检测 | — |
| 注入恶意 class 到 JAR 根 | 能检测 | — |
| 修改 Spring Boot Loader 类 | 能检测 | — |
| 伪造签名文件 | 不可能 | 不可能 |
| 密码错误 | 能检测 | 能检测 |
| .sign 文件丢失 | 跳过（降级） | 仍生效 |

> 第一层覆盖面广（任何字节变化都能检测），第二层是纵深防御（即使 .sign 旁路文件丢失，密码错误和 INDEX 篡改仍会被拦截）。
