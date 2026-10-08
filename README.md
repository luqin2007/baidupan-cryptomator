# 网盘 Cryptomator — 百度网盘 LSPosed 模块

在百度网盘 App（`com.baidu.drive.app`）的**文件页就地读写 Cryptomator 保险库**：
认出 `vault.cryptomator` / `masterkey.cryptomator`，输入口令后把加密目录 `d/` 展示成解密后的
文件名与目录树；下载时自动解密；删除 / 重命名 / 分享等操作透传回**原始密文文件**。

> **状态**：🟡 **P0 / P1 完成，P2 的解锁与遍历已通过真机验证，但 App 里还看不到解密目录** ——
> 侦察阶段结束（`0.10.1-p0b2`），决定架构的事实已在真机上全部钉死，模块也已能自行取到云端文件字节；
> 文件页的「解密」按钮按保险库识别正确出现/消失，但点击后仍是占位提示。
> **P2 的核心（scrypt → AES-KW 解主密钥、`vault.cryptomator` 验签、SIV 文件名解密、整棵目录树遍历）
> 已由模块自己实现**，与官方 cryptofs 在测试保险库上**逐条对拍一致**，并且在 **App 进程内
> 跑出同一份清单**（8 目录 / 21 文件；设备上解锁 2.5 s、遍历 0.1 s）。两个保险库（fixture 与真实那份）
> 都对拍通过。还没做的是把它接进文件页，以及 P3 的内容解密。
> 见 [`tools/p2/README.md`](tools/p2/README.md) 与 [`docs/recon.md`](docs/recon.md) §13。
> 路线图见 [§5](#5-路线图)。
>
> **许可**：[AGPL-3.0](LICENSE)（因为运行期依赖 Cryptomator 官方的 AGPL 库，见 [§7](#7-许可)）

### 免责声明

这是一个针对**你自己账号里自己文件**的互操作性工具。它不修改百度网盘 App 本体、不篡改通信协议、
不绕过任何付费或容量限制、不包含百度或 Cryptomator 的任何代码与资源（原始安装包刻意不入库）。

与百度在线网络技术（北京）有限公司无任何关联，也未获其授权或支持。**主口令只在本机内存中参与
运算，不会落盘、不会外发**；但请自行评估在他人设备或已 root 设备上使用本模块的风险。

---

## 1. 要解决什么

Cryptomator 的 Android 官方客户端需要把整个保险库通过 WebDAV / 云同步落到本地才能访问。
直接对着网盘用则要绕两道坎：

1. 保险库是**云端文件名的密文世界** —— `d/SY/RGEQKQVHFPTPFOF65L6I62FLLYWDS7/` 这种目录，
   文件名是 Base64Url 编码的密文加 `.c9r` 后缀，人在 App 里根本认不出哪个是哪个。
2. 官方 App 没有"就地解密"这条路，只能先同步再打开，等于把密文全量搬一遍。

本模块走的是第三条路：**在网盘 App 内部劫持文件列表与下载管线**，把 Cryptomator 的加解密
做在 App 进程里，用户看到的还是那个熟悉的文件页。

---

## 2. 目标环境（实测）

| 项 | 值 |
|---|---|
| 手机 | Xiaomi Mi 10 Pro |
| 系统 | Android 16（SDK 36），arm64-v8a |
| Root 方案 | KernelSU + Zygisk Next + LSPosed（`lspd`、`zn-zygisk-companion64 zygisk_lsposed` 均在跑） |
| 目标 App | 百度网盘 `com.baidu.drive.app` **13.11.13**（targetSdk 35，包根 `com.baidu.netdisk.*`） |
| 构建 | 手工 `javac` + `d8` + `aapt2` + `apksigner`，**不依赖 Gradle / 不联网** |
| 观测通道 | ⚠️ **只有 `lspd` 的文件日志可靠**：`/data/adb/lspd/log/modules_<ISO>.log`（需 root）。`logcat` 的主环只有 128 KiB，App 启动一次就把它冲掉 |

> 设备上还装有另一个针对同一 App 的第三方模块（`com.xiyunmn.puredupan.hook`）。
> 两者可以共存，但如果日后出现难解释的表现，优先怀疑它。

---

## 3. 侦察结论（每一条都有实测证据）

详见 [`docs/recon.md`](docs/recon.md)。

| 结论 | 证据 |
|---|---|
| 文件页是**纯原生 Android View**，不是 Flutter | `uiautomator dump` 得到 `RecyclerView`×6 / `TextView`×56，资源 ID 完整（`id/filter`、`id/list_recycler_view`、`id/rv_breadcrumb`…），无 `FlutterView` |
| App 里确实有 Flutter，但**不负责文件页** | `libflutter.so`(11 MB) + `libapp.so`(21 MB) 存在；无 `index.android.bundle`/`libhermes.so` → 不是 RN |
| 列表由 **Cursor 驱动** | `com.baidu.netdisk.filelist.repository.CloudFileListLoader extends com.baidu.netdisk.db.cursor.ObjectCursorLoader` |
| 通用文件模型是 **`CloudFile`**，且方法名**未混淆** | `CloudFile.createFormCursor(Cursor)` / `readFromCursor(Cursor, CloudFile)` / `getFilePath()` / `getFileId()` / `isDir()` / `getFileDlink()` |
| 适配器方法名未混淆 | `com.baidu.netdisk.filelist.view.FileListWrapperAdapter` → `getItemCount` / `getItemViewType` / `onBindViewHolder` / `onCreateViewHolder` |
| 保险库是 **format 8 / SIV_GCM / threshold 220** | 解析 `vault.cryptomator`（`jti=b4389b25-…`） |
| 条目名是 **Base64Url**（format 8 起，非老的 Base32） | 实见 `kymd3lVEAXDmA07lgpuoDiebhu6fvHpvkCQ=.c9r`；目录标记为 **`dirid.c9r`** |
| 目录布局 `d/<前2>/<余30>` | 实见 `d/SY/RGEQKQVHFPTPFOF65L6I62FLLYWDS7/`（dirId 32 字符） |
| 官方 `cryptolib-2.2.2` **可以直接上 Android** | 4649 个类中 4647 个是 Java 8（major 52）；BC 已 shade 到 `org.cryptomator.cryptolib.shaded.bouncycastle`；与 `siv-mode` 的 shade 包**无重叠**（唯一重叠是 `module-info.class`） |
| **cryptolib 能打进单个 dex** | `cryptolib` + `siv-mode` 经 d8 产出 **5.8 MB 单个 `classes.dex`**，无重复类、无需 multidex，构建 40 秒 |
| ⚠️ **但"能 dex"不等于"能跑"** | cryptolib 的入口在运行期会向 **guava** 要 `com.google.common.base.Preconditions`（`MasterkeyFileAccess` 还要 gson）。d8 不解析"没人调用"的引用，所以当时模块里没有一个类调用 cryptolib，这个洞在 P0-C 完全看不见 —— P2 真正调用时才暴露（recon §13.3） |
| 模块自带 4 个方法的 `Preconditions` 垫片 | `module/src/com/google/common/base/Preconditions.java`：语义是规范级的；宿主 App 若自带 guava，父加载器优先，我们的版本不会被加载 |
| **`hashDirectoryId` 不是哈希** | `base32(SHA1(SIV_encrypt(encKey, macKey, dirId)))` —— **与密钥有关**，不解锁就算不出根目录在 `d/` 下的位置（recon §13.2a） |

### 3.1 安全 / 反检测

APK 里存在 `libnetdisk-signature-check.so`、`libbaiduprotect_sec.so`、`libmsaoaidsec.so`
以及 Robotium 残留。**反 Xposed 检测是真实风险**，因此 P0 的验收标准之一就是"模块装上后 App
正常不崩不被杀"，而不是留到最后再处理。

---

## 4. 架构与注入点

```
百度网盘 App 进程 (com.baidu.drive.app)
├─ 文件页  FileTabListFragment
│   └─ 工具栏  FileListToolBarHeaderView
│        [智能排序] … [筛选] [网格]        ← 在这里、filter 左侧插入「解密」按钮
│   └─ RecyclerView  id/list_recycler_view
│        └─ FileListWrapperAdapter
│             └─ Cursor ──> CloudFile      ← 每行的模型：fsId / path / name / size / md5
└─ 下载管线  IDownloadable / CloudP2pDlinkApi / DownloadTaskManager
```

注入点已经用**运行时的资源 ID 几何**确认过（`uiautomator dump`）：

| 控件 | 类型 | bounds |
|---|---|---|
| `id/sort` 智能排序 | TextView | `[50,393][182,476]` |
| **`id/filter` 筛选** | ImageView | `[869,393][955,476]` |
| `id/switch_layout_icon` 网格切换 | ImageView | `[958,393][1036,476]` |

「解密」按钮插在 `findViewById(R.id.filter).getParent()` 内、`filter` 之前。

关键设计：解密目录下的每个虚拟条目都会**携带原始 `fsId` 与加密路径**。这样删除 / 重命名 /
分享会自然作用到原始密文上，不需要额外映射表，也不需要反向推算密文文件名。

---

## 5. 路线图

| 阶段 | 内容 | 验收标准 | 状态 |
|---|---|---|---|
| **P0** | 模块骨架 + 运行时探针 + 内容通道侦察 + 打包可行性验证 | 模块能装进 App 进程；探针能吐出全部目标类的**真实签名**；cryptolib 能进 dex；**模块能自己拿到云端文件字节** | ✅ P0-A/B/C/D 全部通过（`0.10.1-p0b2`，2026-10-08） |
| **P1** | 在工具栏注入「解密」按钮，仅当当前目录含 `vault.cryptomator` 时显示 | 进出保险库目录按钮出现 / 消失；点击弹出口令输入 | ✅ 按钮生命周期通过（`v0.9.1-p1`）；弹出的仍是占位提示，真正解锁在 P2 |
| **P2** | 解锁 + 目录遍历 + SIV 文件名解密（模块自己实现，cryptofs 进不了 dex），再在文件页上做成虚拟解密目录 | 与 Cryptomator 桌面版逐条对照，中文名 / 空格 / 多级目录全一致 | 🟡 密码学与遍历**已完成并对拍通过**：离线 `p2.sh check` 与**真机探针报告**都是 8 目录 / 21 文件逐条一致（2026-10-08），反证 4/4；**尚未接进 App**（虚拟目录 / 面包屑未做） |
| **P3** | 下载自动解密：劫持下载完成点，就地解密并还原真实文件名 | 下载 → 拿到可打开的明文 | ⬜ |
| **P4** | 删除 / 重命名 / 分享透传（靠 P2 保留的原始 `fsId`） | 解密态下操作，云端作用于**原密文** | ⬜ |
| **P5** | 上传自动加密（可选） | 桌面版能正常打开上传的文件 | ⬜ |
| **P6** | 收尾：清理、脱敏、文档、release 正式签名 | 公开仓库可复现构建 | ⬜ |

v1 范围是**只读**（浏览解密 + 下载解密），上传加密放到 P5。

---

## 6. 构建

需要：JDK（含 `javac`/`keytool`）、Android SDK（build-tools + 一个 platform 的 `android.jar`）、
bash。Windows 上用 Git Bash 即可。

```bash
# 取运行期依赖（AGPL 的 Cryptomator 库，不入库）
bash module/tools/fetch-libs.sh

# 构建
bash module/build.sh
# -> dist/BdCryptomator-<version>.apk
```

脚本会依次：编译 Xposed API 存根（**只用于编译，不进 dex**）→ 编译模块源码 →
`d8` 把模块类与 `module/libs/*.jar` 一起 dex → `aapt2` 打包资源与清单 →
`zipalign` → `apksigner`（v1+v2+v3）。

签名材料不入库：`module/keystore/` 与 `module/keystore.properties` 都在 `.gitignore` 里。
没有 `keystore.properties` 时脚本会退化成自动生成的 debug key（**debug 签名的 APK 无法覆盖
正式签名的安装**）。

---

## 7. 安装

```bash
adb install -r dist/BdCryptomator-<version>.apk
```

然后**必须手动**在 LSPosed 管理器里给模块勾选作用域：

```
LSPosed → 模块 → 网盘 Cryptomator → 作用域 → 勾选「百度网盘」
```

> ⚠️ 这一步无法自动化：`adb shell` 在本机拿不到 root，写不了 `/data/adb/lspd/` 下的作用域配置。
> 清单里的 `xposedscope` 只是**推荐**作用域提示，LSPosed 不会替你勾。

勾选后**强制停止**一次 App 才会重新加载模块：

```bash
adb shell am force-stop com.baidu.drive.app
adb shell am start -n com.baidu.drive.app/com.baidu.netdisk.ui.DefaultMainActivity
```

看日志请读 **`lspd` 的文件日志**，不是 logcat：

```bash
adb shell su -c 'ls -t /data/adb/lspd/log/modules_*.log | head -1'   # 最新一份
```

看到 `=== BdCryptomator attached: pkg=com.baidu.drive.app ... ===` 就说明模块活了。

> **不要用 `logcat -s BDCrypto:V` 判断模块是否加载。** 实测 `main` 环形缓冲只有 128 KiB，
> 网盘启动一次就把它冲干净，之后只会看到空结果 —— 这会得出"模块挂了"的错误结论
> （我就是这么误判过一次，详见 `docs/recon.md` §8.1）。
> `logcat` 只适合启动后几秒内的即时观察。

### 7.1 校验下载的 APK

发布件用固定的正式密钥签名（RSA-4096 / SHA256withRSA）。装之前请核对指纹，确认拿到的是本仓库的构建：

| 项 | 值 |
|---|---|
| 证书 SHA-256 | `9A:34:AD:E0:AC:34:FC:87:8B:89:AC:31:AA:16:B2:C7:6C:F8:02:3B:E7:AF:48:A2:3C:F1:03:0F:B2:1F:31:ED` |
| 证书 SHA-1 | `DD:E8:B7:04:BF:40:12:06:FB:2D:5C:A7:14:BD:84:E8:A0:A0:6B:E5` |

```bash
apksigner verify --print-certs BdCryptomator-<version>.apk | grep SHA-256
sha256sum BdCryptomator-<version>.apk     # 与 release notes 里的值比对
```

> ⚠️ 签名私钥不在仓库里（`module/keystore/` 被 `.gitignore` 挡住），细节见
> [`module/tools/README-signing.md`](module/tools/README-signing.md)。
> **先装过 debug 签名版本的话，必须先卸载**才能装正式签名版。

---

## 8. 运行时探针（开发用）

重装一次模块要 30 秒以上（构建 → 安装 → 重启 → 重新勾选）。逆向阶段需要反复问运行中的 App
几十次问题，所以模块暴露了一个**动态注册**的广播接收器（只在 App 进程存活期间存在）：

```bash
ADB="$ANDROID_HOME/platform-tools/adb.exe"
B='am broadcast -a com.luqin.bdcrypto.PROBE'

"$ADB" shell "$B --es cmd help"
"$ADB" shell "$B --es cmd selftest"                       # 逐一解析模块关心的所有类
"$ADB" shell "$B --es cmd dump --es cls <完整类名>"        # 真实成员签名 -> 报告文件
"$ADB" shell "$B --es cmd classes --es cls 'download.*Api'" # 搜索内置的全量类名索引
"$ADB" shell "$B --es cmd graph"                           # FileTabListFragment 的对象图
"$ADB" shell "$B --es cmd items"                           # 已捕获的 CloudFile 行
"$ADB" shell "$B --es cmd state"
"$ADB" shell "$B --es cmd ls"                              # 报告文件列表
"$ADB" shell "$B --es cmd vault --es arg /sdcard/Download/BaiduNetdisk/p0d-fixture=<口令>"
                                                           # P2：在设备上解锁 + 遍历，报告 -> vault.txt
```

大批量输出不写 logcat（会被截断、会插进 App 自己的日志），而是写到 App 自己的外部目录：

```
/sdcard/Android/data/com.baidu.drive.app/files/bdcrypto/*.txt
```

可以非 root `adb pull` 出来。

---

## 9. 仓库结构

```
module/
  src/com/luqin/bdcrypto/    模块源码
    BdCryptoModule.java        Xposed 入口（唯一职责：认包名 → 交给 Hooks）
    Hooks.java                 所有 hook：文件页生命周期 / 适配器 / CloudFile / Cursor / 网络
    Probe.java                 探针命令集
    ProbeReceiver.java         动态广播接收器（开发期交互通道）
    Reflectx.java              反射辅助：完整签名渲染、对象图遍历
    Report.java                报告文件写出
    Logx.java                  日志（logcat + LSPosed 双通道，长文本分片）
    vault/                     P2：保险库实现（解锁 / 目录遍历 / 文件名解密）
                               无 Android 依赖，cryptofs 进不了 dex 所以这里自己写
  src/com/google/common/base/Preconditions.java   cryptolib 运行期要的 4 个 guava 方法（垫片）
  stubs/de/robv/…             Xposed API 编译期存根（不进 dex）
  res/ assets/                xposed_init 与全量类名索引
  tools/dexdump.py            dex 分析工具（见下）
  tools/fetch-libs.sh         取 AGPL 运行期依赖
  build.sh                    全流程构建
tools/dexdump.py              离线 dex 逆向工具
tools/oracle/                 桌面端 Cryptomator 参考工具：验口令 / 出明文清单 / 造测试保险库
tools/p2/                     离线对拍：用模块自己的遍历走保险库，与 oracle 的清单 diff
docs/recon.md                 侦察原始记录
```

### `tools/oracle/`

模块不能打包 `cryptofs`（要 `java.nio.file`、guava、jackson），目录遍历必须自己实现。
这个目录下三个程序用**官方** cryptolib + cryptofs 在桌面 JVM 上做同一件事，因此是那套自研
实现的裁判，同时给出每个密文文件**应有的明文**：

```bash
tools/oracle/oracle.sh check  <保险库> '<口令>'    # 口令对不对（手工重做 scrypt + AES-KW + versionMac）
tools/oracle/oracle.sh unlock <保险库> '<口令>'    # 明文 <-> 密文对照清单
tools/oracle/oracle.sh make   <保险库> '<口令>'    # 造 P0-D 测试保险库
```

需要 **JDK 25**（cryptofs 是 class file 69）与本地 Cryptomator 安装的 jar。
保险库结构与体积模型的实测结论见 [`docs/recon.md`](docs/recon.md) §12 与
[`tools/oracle/README.md`](tools/oracle/README.md)。

### `tools/p2/`

P2 的验收工具：把**模块自己的** `vault/` 源码编译起来（classpath 里**故意没有 `android.jar`**），
走一遍测试保险库，再与 `tools/oracle` 的清单逐条 diff。

```bash
bash tools/p2/p2.sh walk  /d/cryptomator/p0d-fixture '<口令>'   # 模块解出来的树
bash tools/p2/p2.sh check /d/cryptomator/p0d-fixture '<口令>'   # 与官方 cryptofs 对拍
bash tools/p2/p2.sh check-report /d/cryptomator/p0d-fixture '<口令>' <从手机拉回来的报告>
bash tools/p2/p2.sh negative /d/cryptomator/p0d-fixture '<口令>' # 反证：4 种故障必须被抓住
```

当前结果：**29 条（8 目录 + 21 文件）逐条一致** —— 桌面上如此，**真机（App 进程内）拉回来的报告
也如此**，且都是 0 warning。设计理由与覆盖范围见 [`tools/p2/README.md`](tools/p2/README.md)。

### `tools/probe.sh` 与 `tools/ui.py`

真机开发期的左右手。`probe.sh` 向 App 进程里的模块发一条命令并打印它的回答：

```bash
tools/probe.sh ch last     # P0-B 捕获总览 + 全部去重签名
tools/probe.sh ch hier     # 每个捕获对象的类型图 —— 读 R8 混淆类的唯一手段
tools/probe.sh dump <类名>  # 该类的完整真实签名
```

回答读的是 **LSPosed 自己的模块日志**（`/data/adb/lspd/log/modules_*.log`，需 root/ssh），
不是 logcat —— `main` 环形缓冲只有 128 KiB，App 启动一次就冲干净，据此判断"模块挂了"
会得出完全错误的结论（本项目误判过一次）。

`ui.py` 按现取坐标驱动界面（`dump` / `find` / `tap` / `long` / `back`）。
两者都需要 root 或 ssh 才能用，纯开发期工具。

### `tools/dexdump.py`

与"扫字符串池"的做法不同，它真正解析 dex 结构，因此能拿到 R8 之后仍然可靠的信息：

```bash
python tools/dexdump.py --dex <含 classes*.dex 的目录> methods <类名>   # 完整签名
python tools/dexdump.py --dex <dir> impl    <接口名>                    # 实现类（读 interfaces_off）
python tools/dexdump.py --dex <dir> sig     <正则>                      # 全量方法签名搜索
```

`impl` 是它存在的核心理由：`IDownloadable` 的实现类既不是子类也没有可读的名字，
只有读 `interfaces_off` 才找得到。

---

## 10. 许可

**AGPL-3.0**，见 [LICENSE](LICENSE)。

之所以不是 MIT：模块在运行期直接依赖 Cryptomator 官方的 [`cryptolib`](https://github.com/cryptomator/cryptolib)
与 [`siv-mode`](https://github.com/cryptomator/siv-mode)（都是 AGPL-3.0）。用官方的实现而不是
自己重写 AES-SIV / AES-GCM / scrypt 组合，是为了让**密码学正确性**由上游保证 —— 代价就是本仓库
整体必须 AGPL-3.0。

> 边界：**scrypt（`cryptolib`）与 AES-SIV（`siv-mode`）用官方的**；自研的是周边那些"写错了会立刻
> 报错"的部分 —— RFC 3394 密钥解包（正确性由 `versionMac` 反向保证）、base32 / base64url、
> `masterkey.cryptomator` 的字段读取、以及目录遍历本身。cryptofs 无法进 dex，遍历注定要自己写。

这些库**不入库**：构建时由 `module/tools/fetch-libs.sh` 从本地 Cryptomator 安装目录复制，
或从 Maven Central 下载。

本仓库不含百度网盘、Cryptomator 的任何代码、资源或商标。Cryptomator 是 Skymatic GmbH 的商标。
