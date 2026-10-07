# 侦察记录（P0）

本文只记录**实测**结论与获得它的命令，供复现。推测一律标注为推测。

---

## 1. 设备与框架

```bash
ADB="$ANDROID_HOME/platform-tools/adb.exe"
"$ADB" devices -l
"$ADB" shell getprop ro.build.version.release        # 16
"$ADB" shell getprop ro.build.version.sdk            # 36
"$ADB" shell getprop ro.product.cpu.abi              # arm64-v8a
```

Root 与框架（`su` 在 adb shell 下**不可用**，所以只能读进程与包清单）：

```bash
"$ADB" shell "pm list packages -u | grep -i -E 'lsp|xposed|magisk|riru|zygisk|kernel'"
#   me.weishu.kernelsu           -> KernelSU
"$ADB" shell "ps -A -o NAME | grep -i -E 'lsp|zygisk'"
#   lspd
#   zn-zygisk-companion64 zygisk_lsposed
```

结论：**KernelSU + Zygisk Next + LSPosed**，KernelSU 管理器 `me.weishu.kernelsu`。
设备上已存在另一个针对本 App 的模块 `com.xiyunmn.puredupan.hook`（LSPosed 日志里可见）。

---

## 2. 目标 App

```bash
"$ADB" shell dumpsys package com.baidu.drive.app | grep -E 'versionName|targetSdk|codePath'
#   versionName=13.11.13   targetSdk=35
"$ADB" shell cmd package resolve-activity --brief com.baidu.drive.app
#   com.baidu.netdisk.ui.DefaultMainActivity
```

APK 是 split 包（base + `split_config.arm64_v8a`）。base.apk ≈ 243 MB。

```bash
"$ADB" shell "unzip -l <base.apk> | grep -i -E 'index.android.bundle|hermes|reactnative'"
#   无输出 → 不是 React Native
"$ADB" shell "unzip -l <split.apk> | grep '\.so$'"
#   libflutter.so (11 MB), libapp.so (21 MB)  → Flutter AOT release 存在
#   libmml_framework.so                        → 百度 MML 动态化框架
#   libjni-kservice.so (34 MB)                 → 业务 native 模块
#   libnetdisk-signature-check.so, libbaiduprotect_sec.so, libmsaoaidsec.so
```

---

## 3. 文件页是原生 View（决定性）

```bash
# 切到「文件」标签后
"$ADB" shell input tap 400 2270
"$ADB" shell "uiautomator dump --compressed /sdcard/ui_file.xml"
"$ADB" pull /sdcard/ui_file.xml
grep -oE 'class="[^"]+"' ui_file.xml | sort | uniq -c | sort -rn | head
#   6 androidx.recyclerview.widget.RecyclerView
#  56 android.widget.TextView
#      ImageView / ImageButton / android.view.ViewGroup …
```

**没有 `FlutterView`** —— Flutter 不负责文件页。资源 ID 完整可用：

| 资源 ID | 类 | bounds |
|---|---|---|
| `id/sort` | TextView | `[50,393][182,476]` |
| `id/filter` | ImageView | `[869,393][955,476]` |
| `id/switch_layout_icon` | ImageView | `[958,393][1036,476]` |
| `id/list_recycler_view` | RecyclerView | 列表本体 |
| `id/rv_breadcrumb` | — | 面包屑 |

---

## 4. 关键类（dex 静态分析）

提取 dex 后用 `tools/dexdump.py`：

```bash
"$ADB" pull <base.apk>
python -c "…解出 20 个 classes*.dex…"
python tools/dexdump.py --dex recon/dex classes 'netdisk/(allfiles|filelist)/.*'
```

方法名**部分混淆**：R8 把合成类改名为 `a` / `a0` / `_`，但下面这些保留了实名：

| 类 | 说明 |
|---|---|
| `com.baidu.netdisk.allfiles.listfragment.FileTabListFragment` | 文件页 Fragment |
| `…allfiles.listfragment.extraview.header.FileListToolBarHeaderView` | 工具栏（方法全混淆，只能 hook `<init>`） |
| `com.baidu.netdisk.filelist.view.FileListWrapperAdapter` | 列表适配器（`getItemCount`/`onBindViewHolder`/`onCreateViewHolder` 干净） |
| `com.baidu.netdisk.swipeback.view.NetDiskFileListFragment` | 基类（`getFileListFacade$…` → Cursor 驱动） |
| `com.baidu.netdisk.filelist.repository.CloudFileListLoader` | `extends com.baidu.netdisk.db.cursor.ObjectCursorLoader` |
| **`com.baidu.netdisk.cloudfile.io.model.CloudFile`** | 通用文件模型，方法名**未混淆** |

`CloudFile` 的关键成员：

```
static CloudFile createFormCursor(android.database.Cursor)
void            readFromCursor(android.database.Cursor, CloudFile)
String          getFilePath() / getFileName() / getServerMD5() / getFileDlink()
long            getFileId() / getSize() / getServerMTime()
int             isDir()
```

### 4.1 下载管线

```bash
python tools/dexdump.py --dex recon/dex impl com.baidu.netdisk.transfer.base.IDownloadable
#   com/baidu/netdisk/cloudfile/io/model/CloudFile     <- CloudFile 就是"可下载对象"
#   com/baidu/netdisk/transfer/url/transfer/UrlDownloadable
```

`IDownloadable` 的方法名干净（`getFileDlink` / `getFilePath` / `getFileId` / `getSize`），
但真正干活的类被混淆了：

- `com.baidu.netdisk.transfer.download.SingleFileDownloadHelper` → 方法只有 `<init>`/`_`/`__`/`a`/`b`
- `com.baidu.netdisk.transfer.task.DownloadTaskManager` → 同上
- `com.baidu.netdisk.file.download.component.apis.FDDownloadManagerApi` → 同上

**推论（待 P0-B 运行时验证）**：对混淆类只能用**描述符**定位，这正是 `dexdump.py`
渲染完整签名的原因，也是模块内置探针（`dump <class>`）要在真机上跑一遍的原因 ——
运行时的 `getDeclaredMethods()` 比反编译输出更可信。

dlink 的取得路径存在多个候选，均为 "caller / provider" 成对出现（Baidu 的组件化框架）：

- `com.baidu.netdisk.cloudp2p.component.provider.CloudP2pDlinkApi.getDlinkByTaskId(int, String, String)`
- `com.baidu.netdisk.transfer.transmitter.locate.LocateDownloadUrls`
- `com.baidu.netdisk.transfer.io.model.LocateDownloadResponse`

---

## 5. 保险库格式（实测本机 `D:/cryptomator/baidu/`）

`vault.cryptomator`（JWT 形式的 JSON）：

| 字段 | 值 |
|---|---|
| `format` | **8** |
| `cipherCombo` | **SIV_GCM** |
| `shorteningThreshold` | **220** |
| `jti` | b4389b25-022e-42aa-8087-bbb29b07e22b |

`masterkey.cryptomator`：纯 JSON，`version=999`，scrypt `cost=32768 / blockSize=8`，
`primaryMasterKey` 与 `hmacMasterKey` 各 40 B（AES-KW wrap 后 → 32 B 明文），`versionMac` 32 B。

目录结构：

```
vault.cryptomator
masterkey.cryptomator
d/SY/RGEQKQVHFPTPFOF65L6I62FLLYWDS7/dirid.c9r
```

- 布局是 `d/<dirId 前 2 字符>/<后 30 字符>`，dirId 共 32 字符
- 目录标记文件是 **`dirid.c9r`**（不是旧版的 `dir.c9r`）
- 条目名形如 `kymd3lVEAXDmA07lgpuoDiebhu6fvHpvkCQ=.c9r` —— **Base64Url**，不是旧版的 Base32

---

## 6. 官方库能否上 Android

```bash
ls "/c/Program Files/Cryptomator/app/mods/"
#   cryptolib-2.2.2.jar  6.9 MB
#   siv-mode-1.6.1.jar   2.7 MB
#   （Cryptomator 1.19.3 桌面版自带）
```

字节码版本统计（读每个 `.class` 的 major version）：

| jar | 类数 | 结论 |
|---|---|---|
| `cryptolib-2.2.2` | 4649 | 4647 个 major 52（Java 8），2 个 `module-info.class`（Java 9/22，d8 会忽略） |
| `siv-mode-1.6.1` | 1107 | 全部 Java 8 |
| `gson` / `guava` / `slf4j` | — | 全部 Java 8 |

shade 情况：

- `cryptolib` → `org.cryptomator.cryptolib.shaded.*`（4588 类）
- `siv-mode` → `org.cryptomator.siv.org.*`（1094 类）
- 两者**无重叠**（唯一交集是 `META-INF/versions/9/module-info.class`）

`cryptolib` 同时含 `v1/`（format 7 / Base32 名）与 `v2/`（format 8 / Base64Url 名）两套实现，
正好覆盖本保险库的 format 8。

打包实测：`d8 --min-api 24` 把两个 jar 与模块类一起产出 **单个 5.8 MB `classes.dex`**，
无重复类错误、无需 multidex，构建 40 秒。→ **P0-C 通过**。

---

## 7. 待运行时验证的问题（P0 的剩余目标）

静态分析到此为止，剩下三件事只有跑起来才知道：

1. **`FileTabListFragment` 的对象图** —— 谁持有 adapter、谁持有当前路径状态。
2. **`CloudFile` 工厂是否真的覆盖列表行** —— `createFormCursor` / `readFromCursor`
   的调用时机与入参形态；Cursor 的列名集合。
3. **内容读取通道** —— 在混淆的下载管线里，哪一条反射调用能"给定云端路径 → 拿到字节"。

模块内置的探针正是为回答这三个问题而写的。

---

## 8. 真机跑起来之后推翻的三个判断（2026-10-07 晚）

第一次真机运行把三条"推论"改成了"实测"，其中两条是我自己写错的。

### 8.1 观测通道：logcat 不可靠，模块日志要看 `lspd`

M0 期间我在 16:25–16:32 用 `adb logcat -s BDCrypto:V` 判定"框架不再注入模块"，
据此提出"需要重启设备"。**这个结论是错的。** 事后从设备上读到：

```
BdCryptomator attached 的次数：12
16:19:37 / 16:19:42 / 16:21:09 / 16:21:12 / 16:24:39 / 16:24:43
16:25:05 / 16:25:09 / 16:25:44 / 16:25:48 / 16:33:44 / 16:33:47
```

我"判定已死"的那几分钟里，模块**每一次都在正常注入**。原因是观测手段：

```
main: ring buffer is 128 KiB ... 当前可读行数 = 54
```

网盘启动一次就会把 128 KiB 的 logcat 主环冲掉，随后在 `-d` 里什么也看不见。
而 LSPosed 的模块日志真正落在 `/data/adb/lspd/log/modules_<ISO>.log`
（本次是 `modules_2026-10-07T10:53:31.831644.log`）。

> **结论：诊断本模块只有一条可靠通道 —— `lspd` 的文件日志，需要 root 读取。**
> `logcat` 只能用于"启动后几秒内"的即时观察。

### 8.2 工具栏不是 `top_bar_layout`，是列表的一个 header item

`id/sort`（智能排序）与 `id/filter`（筛选）的**父容器是 `LinearLayout id=container`，
而 `container` 又挂在 `RecyclerView id=list_recycler_view` 下** —— 也就是说这一行是
列表的 header，由 `FileListToolBarHeaderView` 渲染（它内部那个 `$_` 是个
`RecyclerView.Adapter`，正好对上）。

`top_bar_layout` 里只有 `tv_my_wangpan` 与 `rv_breadcrumb`。

右侧空间已近饱和（`filter` 右边界 955、`switch_layout_icon` 右边界 1036、屏宽 1080），
**盲插一个同宽按钮（86px）会把 `switch_layout_icon` 挤出屏幕**。
所以插入位置必须等运行时视图树确认，不能照静态 dump 下手。

### 8.3 `hookAllMethods(cls, null, cb)` 不存在

P0 的下载通道 hook 全部失败：

```
[target] hook ...SingleFileDownloadHelper failed:
         java.lang.NullPointerException: methodName cannot be null
```

Xposed 没有"hook 该类全部方法"的 API；`hookAllMethods` 收的是**方法名**，LSPosed 对 null 直接抛。
正确做法是枚举 `getDeclaredMethods()` / `getDeclaredConstructors()` 逐个 `hookMethod(Member, cb)`。

### 8.4 顺带修正：stub 的返回类型必须与框架一致

`XposedBridge.hookMethod` 的真实签名（直接读设备上的
`/data/adb/modules/zygisk_lsposed/framework.dex` 得到，LSPosed v2.1.1 / 7790）：

```
java.util.Set            hookAllMethods(Class, String, XC_MethodHook)
java.util.Set            hookAllConstructors(Class, XC_MethodHook)
XC_MethodHook$Unhook     hookMethod(Member, XC_MethodHook)
void                     log(String)
```

我原先的 stub 把 `hookMethod` 写成 `void` —— 那样 d8 会生成一个**运行时不存在的方法原型**，
首次调用即 `NoSuchMethodError`。已修正，并在构建产物里逐条比对过方法引用。

### 8.5 列表 Cursor 的真实形态

`CloudFile` 工厂的入参 Cursor 类名被混淆（`hm.____`），列名完整可读：

```
_id, fid, server_path, file_name, isdir, state, file_category, file_property,
parent_path, blocklist, file_md5, s3_handle, file_size, server_ctime, server_mtime,
client_ctime, client_mtime, file_download_state, ...
```

行内实测可取到 `fsId / path / name / mtime / md5`（含中文名），
这正是后续要透传回原密文所需的那组身份字段。

### 8.6 下载管线的活体签名

```
SingleFileDownloadHelper
    __(String, ResultReceiver)          ____(String)          ___(String) : String

DownloadTaskManager  (继承 IDownloadable 相关)
    f(IDownloadable, IDownloadProcessorFactory, TaskResultReceiver, int)
    d(List, IDownloadProcessorFactory, TaskResultReceiver, int)
    e(List, IDownloadProcessorFactory, TaskResultReceiver, int, ITaskStateCallback)

FDDownloadManagerApi      (51 个方法，Kotlin 编译产物)
    l(IDownloadable, IDownloadProcessorFactory, TaskResultReceiver, int)

CloudP2pDlinkApi
    getDlinkByTaskId(int, String, String)
    getShareDownloadDlink(String, String, long[], String, ...) : ArrayList
```

`IDownloadable` 的方法名是干净的（`getFileDlink` / `getFilePath` / `getFileId`），
且 `CloudFile` 实现了它 —— 所以"给定一个 CloudFile，让 App 自己去下载"这条路有明确入口。
P0-B 的判断留给下一版的运行时调用图。
