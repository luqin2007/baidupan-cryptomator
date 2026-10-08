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

## 9. 工具栏副本的真实结构（2026-10-07 深夜，`copies` 探针实测）

§8.2 只说了"工具栏是列表 header"，不够。探针把窗口里**每一个** `id/filter` 连它的祖先链
逐层打印之后，真相是：

**一次 `/crypto/content` 的列表面板，窗口里有 4 个 `id/filter`、3 个页面容器、2 个面包屑。**

```
ConstraintLayout (kids=3  filters=4  crumbs=2)          ← 页面容器们的公共父
├── FrameLayout#filelist_container3 ... SwipeBackLayout → RelativeLayout#root (kids=13 filters=2 crumbs=1)
│     ├── FileListRecyclerView#list_recycler_view → LinearLayout#container → … → UISVGView#filter   shown=false
│     └── UILinearLayout#empty_headers            → LinearLayout#container → … → UISVGView#filter   shown=false
└── FrameLayout#filelist_container2 ... SwipeBackLayout → RelativeLayout#root (kids=13 filters=2 crumbs=1)
      ├── FileListRecyclerView#list_recycler_view → LinearLayout#container → … → UISVGView#filter   shown=true   ← 在屏的那份
      └── UILinearLayout#empty_headers            → LinearLayout#container → … → UISVGView#filter   shown=false
```

### 9.1 一页有两套工具栏，不是一套

`list_recycler_view` 里那套是列表非空时用的；`empty_headers` 里还有一套同构的，
列表为空时显示。两套都带完整的 `sort / filter_dialog_enter / filter`，
且**两套都属于同一页**（同一个 `RelativeLayout#root`，`crumbs=1`）。

后果：任何"数这一层有几个 `id/filter`"的规则都会把一页当成两页。
`pageRootOf` 最初写成"爬到第一个含 ≥2 个 `id/filter` 的祖先之前停下"，
于是在 `list_view_bg_layout` / `empty_headers` 就停了 —— 而这两层 `crumbs=0`，
`findViewById(rv_breadcrumb)` **永远返回 null**，四份副本全部无法归属，按钮一次都没插进去。

**正确规则**：页根 = **最内层**"恰含 1 个 `id/rv_breadcrumb`"的祖先。
实测它正好落在 `RelativeLayout#root`，两套工具栏都归到同一页，正是想要的语义。
再往上爬会碰到那个 `filters=4 crumbs=2` 的 `ConstraintLayout`，
从那里 `findViewById` 就可能取到隔壁页的面包屑。

### 9.2 面包屑是唯一的区分手段

四份副本的 class、各级祖先的资源 id、bounds **全部相同**，几何和类型都分不出来。
只有 `rv_breadcrumb` 里的文字能说它是哪一页：

```
copy 0 / copy 1 : crumb = /crypto          ← filelist_container3
copy 2 / copy 3 : crumb = /crypto/content  ← filelist_container2（copy 2 shown=true）
```

`rv_breadcrumb` 是 `RecyclerView`，item 结构 `LinearLayout → TextView#content`，
文字是目录名。注意它**带上抽屉根节点**：`/crypto/content` 这一页读到的是
`我的网盘/crypto/content`（三个 item），所以匹配用后缀不能用相等。

### 9.3 `isShown()` 只能滤掉空态工具栏，判断不了哪一页画在屏上

这一条是 §9.2 之后的第一次修正，**它自己后来又被 §9.4 修正了一次**。

同页两套工具栏 crumb 相同、都"匹配"，但 `empty_headers` 那套 `shown=false`、`w=0`。
把按钮放进去就是这个模块踩得最久的坑：**树里有、`clickable=true`、
`uiautomator` 里查得到，但屏幕上什么都没有**。所以"归属对了"还不够，必须再筛一次
`isShown()` —— 这一步是对的，至今仍在用（`attachUnlockButtons` 里对 `isTarget[]` 的第二次扫描）。

**但它只够滤掉空态工具栏，不够定位"当前页"。** 反例（`copies` 探针，从
`/crypto/content` 退回 `/crypto` 的稳定态）：

```
copy 0: crumb=/crypto          filter_layout shown=true   ← filelist_container3
copy 1: crumb=/crypto          shown=false                ← empty_headers in container3
copy 2: crumb=/crypto/content  filter_layout shown=true   ← filelist_container2
copy 3: crumb=/crypto/content  shown=false                ← empty_headers in container2
```

`copy 0` 与 `copy 2` **同时 `shown=true`**，因为它们都是 `VISIBLE` 且 attached 的，
只是一个被另一个画在了上面。`RecyclerView` 之外根本没有"这块被遮住了"的状态可读。

后果（真实发生过）：`reconcile` 第一版"取第一个 `isShown()` 的副本"，
于是永远取到 `copy 0` = `/crypto`，判成"当前页不是保险库" → 刚插上的按钮立刻被扫掉，
表现为 **按钮怎么也不出现**。

### 9.4 绘制顺序 = 子索引顺序，最后一个 drawn 的副本才是当前页

判据不在 `isShown()` 里，在**父容器的子列表顺序**里。实测：
app 把当前页的容器**移到它父容器子列表的末尾** ——
`filelist_container3` 在过渡期报 `idx=2/3`，稳定后又报 `idx=1/3`；
而一个 `ViewGroup` 里**后置的子视图画在前置之上**，深度优先遍历又是按子索引走的。

所以：**从后往前遍历副本，第一个 `isShown()` 且 crumb 可读的，就是绘制页。**
`copies` 探针为了支持这个判断，在祖先链里加了 `idx=<i>/<n> z=<z>`
（`indexOfChild` / `getZ`）。

```java
for (int i = copies.size() - 1; i >= 0; i--) {   // 后遍历者画在上层
    android.view.View f = copies.get(i);
    if (!f.isShown()) continue;
    String crumb = crumbPathOf(f, idFilter, idCrumb);
    if (crumb != null) { drawn = crumb; drawnCopy = f; break; }
}
```

`z` 顺带确认了用 `getZ()` 判层级在这套布局里**不成立**：几份副本的 `z` 相同（都是 0），
所以只有 `indexOfChild` 能区分。

### 9.5 走出保险库目录不会触发任何回调 —— 触发点只能是面包屑

`detectVault` 只在**看到** `vault.cryptomator` / `masterkey.cryptomator` 时被调用。
用户从 `/crypto/content` 按返回键到 `/crypto`，新目录不是保险库，
**没有任何代码路径会再去管那个按钮** —— 实测它就一直留在窗口里
（`[641,398][767,470]`，离屏不可见，但 `uiautomator` 里还在）。

关键是：**这个方向连 `detectVault` 都不会被叫到**，两条看起来存在的触发路径实测都断了：

| 本来指望的触发 | 实测结果 |
|---|---|
| 行路径（`CloudFile` 构造）→ `detectVault` | 退回 `/crypto/content` **没有任何新 `CloudFile`** —— 列表走缓存，行不重建，识别不触发 |
| fragment 生命周期（`onResume` 等） | 退回时**没有任何 fragment 事件** —— 页面 view 被保留，只是换了数据源 |

唯一每次都变的是**面包屑**：它的 item 正文就是目录名。
所以 P1 的行路径触发（`noteListingDir` / `dirOf(path)` + 延迟 300 ms 清扫）**整体删除**，
换成 hook `com.baidu.netdisk.ui.breadcrumb.BreadcrumbAdapter#onBindViewHolder` 驱动的
对账（§9.7）。hook 类而不是实例，因为每个文件页都会 `setAdapter` 一个新的，
hook 类才能覆盖后面才建出来的页。

延迟仍然必要（现在是 250 ms，去抖）：到达一个目录时，
面包屑 rebind、第一条 `CloudFile`、fragment resume 会**几乎同时**打过来，
而此刻 app 还在换页，抢第一个会读到**正在离开的那一页**的面包屑。

### 9.6 同一目录可能有两页都 `shown=true` —— 必须按"页根"限幅，否则插出两颗按钮

实测（`/crypto/content` 退回后的某个瞬间）：4 份副本**全部** crumb=`/crypto/content`，
其中 `copy 0`（`container3`）与 `copy 2`（`container2`）**都 `shown=true`**。
它们属于**两个不同的页面容器**，只是碰巧在显示同一个目录。
不加约束就会给两份都插按钮 —— 同一坐标两颗，一颗盖住另一颗，
树里 `解锁=2`，点下去命中哪个不可控。

判据是**页根**（§9.1 的定义：最内层恰含 1 个 `rv_breadcrumb` 的祖先）。
`attachUnlockButtons` 因此多了一个 `pageRoot` 参数，只对"与绘制页同根"的副本动手：

```java
boolean mine = pageRoot == null
        || pageRootOf(copies.get(i), idFilter, idCrumb) == pageRoot;
```

### 9.7 对账（reconcile）：按钮的全部状态由"绘制页的面包屑"推导

这是 P1 收敛到的架构，`Hooks.reconcile(why)` 是唯一的写入口。

放弃"事件流驱动"不是风格选择，是 §9.5 的实测逼出来的：事件两个方向都不可靠。
既然如此，就不要让按钮状态散落在事件之间，改成**每次从一个始终可读的事实重新推导**：

```
绘制页的面包屑 → 它是不是保险库目录？
  ├─ 是 → 只在该页同根、且 isShown 的副本上放按钮（其余副本撤掉）
  └─ 否 → 窗口里所有副本上的自有按钮全部撤掉
```

几个实现要点：

- **身份挂在 view 上，不记引用。** 注入的子视图都打 `TAG_UNLOCK`，
  "这个工具栏有没有按钮"直接问工具栏自己。旧的 `volatile View unlockButton`
  单引用被删掉：一份窗口里有 4 个 `id/filter`、分属 3 个页面容器，
  单个引用在大多数时候描述的都是错的那一份。
- **`sweepAllOurButtons` 清全部副本，不只清绘制页。** 只是"停止被列出"的页仍在窗口里，
  留在它身上的按钮会在 app 把那页拿回来时**复活**。
- **`reconcileSoon` 去抖。** 一个 `AtomicBoolean` pending 标志，触发点只有两个：
  面包屑 `onBindViewHolder`、fragment `onViewCreated|onResume`。一个待处理 pass 足够 ——
  后来的触发只是把它往后挪，pass 本身会重新从树里读一遍。
- **重试链只为"等这一页安定"。** `armedButtons`（当前按钮数）、`lastWantedDir`
  （这次要的是哪个目录）、`retryInFlight`/`retryLeft`（`MAX_SHOWN_RETRIES = 40`）。
  一旦绘制页换成别的目录，这条问题就没有答案了，链自己停。
- **日志去重。** `lastLoggedOutcome` + `logOnce`，避免 40 次重试刷出 40 行一样的字。

`btn off` 与 `btn diag`（= `copies` 探针）都直接走这套，见 §10。

### 9.8 附带发现：版本号在清单里硬编码会静默生效

见 §8 之外的独立提交。`aapt2` 的 `--version-code/--version-name`
**只在清单没声明时**才生效；清单里写了就静默忽略命令行的值。
三个构建全部自称 `0.1.0-p0`，也是"模块更新后不重载"的一部分原因。
现在 `build.sh` 会用 `aapt2 dump badging` 读回链接产物并断言，不符即 `die`。

## 10. 探针命令与 P1 回归（`0.9.1-p1`）

观测通道见 §8.1，命令通过广播下发：

```bash
adb shell am broadcast -a com.luqin.bdcrypto.PROBE --es cmd <cmd> [--es arg <arg>]
```

`copies`（= `btn diag`）是本轮新加的，也是 §9 全部结论的来源。
它按**绘制顺序的逆序**列出窗口里每一份 `id/filter`：

```
copy 2: <class> shown=true  crumb=/crypto/content  parent=<class> id=filter_layout wh=174x83
        chain: ... idx=2/3 z=0.0 ...
        children of parent: [id=sort] [id=filter_dialog_enter] [id=filter] [OURS id=? wh=126x72]
        <含 button 时的：absolute rect / alpha / 文字色>
```

为了判定绘制顺序，祖先链里带 `idx=<i>/<n>` 与 `z=<z>`（`indexOfChild` / `getZ`）——
就是 §9.4 那条结论的证据形状。`btn` 新增 `diag` 子命令（等价于 `copies`），
`off` 现在会清**全部**副本（§9.7）。

**P1 回归（真机，`0.9.1-p1` / versionCode 13）** 是四步走位 + 一次点击，
每步用 `uiautomator dump` 数 `解锁` 节点数、并对原按钮位取均色验证可见性：

| 步 | 走位 | 面包屑实测 | `解锁` 数 | 原按钮位均色 |
|---|---|---|---|---|
| A | 打开 / 切回文件页，停在 `/crypto/content` | `[['crypto','content'], ['crypto']]` | 1 | `[107,133,244]`（蓝，可见） |
| B | 进入 `/crypto/content/d` | `[['crypto','content','d'], ['crypto','content']]` | 0 | — |
| C | 退回 `/crypto/content` | `[['crypto','content'], ['crypto','content']]` | 1 | `[107,133,244]` |
| D | 退到 `/crypto` | `[['crypto']]` | 0 | `[255,255,255]`（白，已撤净） |
| E | 点按钮 | — | — | Toast：`BdCryptomator：保险库已识别，解锁功能将在下一阶段接入` |

C 步是本轮架构的关键验证：**面包屑数组两个元素内容相同**
（`copy 0` 与 `copy 2` 都在 `/crypto/content`），
正是 §9.6 那个"两页显示同一目录"的场景 —— 靠页根限幅才把 `解锁` 数压回 1。
A/B/D 三步验证 §9.5 的清扫：进目录、退到非保险库目录，
按钮都在 250 ms 对账后消失且**不复活**。

对应日志（LSPosed 模块日志，一行一事实）：

```
[button] placed=1 kept=0 removed=0 of 2 copy/copies of /crypto/content
  copy 0: /crypto/content placed at at=4/8 parent=LinearLayout id=filter_layout wh=174x83
    anchor=filter_dialog_enter; copy 1: /crypto/content no button;
  (breadcrumb bound, drawn page is /crypto/content)
[button] placed: at 641,398-767,470 shown=true w=126 in a 334 px row
[button] swept a button off /crypto/content, which is not /crypto/content/d
```

`anchor=filter_dialog_enter` 说明按钮锚在"筛选"**整组控件的第一个成员**之前，
而不是夹在文字与它自己的图标之间（§8.2 的后续修正）。

P1 到此为止：按钮的出现、消失、不重复、位置、点击回调全部有实测支撑。
下一步是 P0-B 内容读取通道（读 `vault.cryptomator` 全文），见 §7 的剩余目标。

## 11. P0-B 内容读取通道（2026-10-08 凌晨，运行时 `dump` 探针）

§7 的第 3 问："在混淆的下载管线里，哪一条反射调用能'给定云端路径 → 拿到字节'"。
这一节记录已经**实测到**的部分，以及为什么这条路不能靠"自己造参数"走通。

### 11.1 两个否定的结论，先排除掉两条看似好走的路

| 本来以为可以 | 实测 |
|---|---|
| 浏览时 `CloudFile.setDlink` 会被调用，拿到 URL 就能自己 GET | **0 次调用**。dlink 只在真的下载/预览时才解析，光浏览不产生 |
| hook `okhttp3.Request$Builder.build` 观察所有出站 URL | 钩子**装上了**（日志 5 次 `hooked okhttp3.Request$Builder.build`），但 `[url]` **0 条** —— App 的 HTTP 流量根本不走 okhttp。这条观测路是死的 |

`okhttp3.OkHttpClient` / `Request$Builder` 都能解析到（`selftest` 19/19），但它们不是 App 的业务网络栈。

### 11.2 运行时真实签名（`dump` 探针，非反编译推测）

`FDDownloadManagerApi`（51 个成员，`public` 无参构造）：

```
l(IDownloadable, IDownloadProcessorFactory, TaskResultReceiver, int)          <- 单文件
e(List, IDownloadProcessorFactory, TaskResultReceiver, int)
g(Activity, boolean, List, IDownloadProcessorFactory, ResultReceiver, int)
______(Activity, boolean, List, IDownloadProcessorFactory, ResultReceiver, int, ITaskStateCallback)
q(List, int, OnProcessListener, Processor$OnAddTaskListener) : IDownloadProcessorFactory
t(String, long, Processor$OnAddTaskListener, int) : IDownloadProcessorFactory
u(IFileInfoGenerator, ITaskGenerator, OnProcessListener) : IDownloadProcessorFactory
r(long, long, long, int, int, int) : IFileInfoGenerator
s(long, long, long, int, int) : ITaskGenerator
v(String, String, String, long, int, int, boolean, String, int) : IFileInfoGenerator
w(List, String, String, String, int) : ITaskGenerator
x() : int    y() : int    z() : String    C()/D() : boolean
```

`DownloadTaskManager`（构造 `(String token, String uid)`，43 个成员）：

```
f(IDownloadable, IDownloadProcessorFactory, TaskResultReceiver, int)          <- 单文件，与上面的 l 同形
d(List, IDownloadProcessorFactory, TaskResultReceiver, int)
e(List, IDownloadProcessorFactory, TaskResultReceiver, int, ITaskStateCallback)
v(List, IDownloadProcessorFactory, TaskResultReceiver, int, ITaskStateCallback)
g(List, IDownloadProcessorFactory, int)
k(IDownloadable, String) : String        o(String, String) : String
```

`SingleFileDownloadHelper`：构造 `(String)`；`__(String, ResultReceiver)`、
`___(String) : String`、`____(String)`。

`ExternalDownloadHelper`（"导出到其他应用"用的单文件下载助手）：
`__(String, long, String)`、`___(String, long, String, Processor$OnAddTaskListener, int)`、
`____(Context, String, long, Uri) : boolean`、`a(Context,String,String)`、
`b(Activity,String,String,String)`、`c(Context,String,String)`。

**反例修正**：`LocateDownloadUrls` 名字像"定位下载地址的网络调用"，实际是个
**`Parcelable` 数据容器**（字段 `host` / `rank` / `url`，方法只有
`describeContents`/`toString`/`writeToParcel`）。§4 把它列为 dlink 候选路径是错的。

### 11.3 为什么不能自己造参数：`Processor` 是抽象类

`IDownloadProcessorFactory` **只有一个方法**：

```
Processor _(IDownloadable, boolean, String, String, int, String)
```

看着很小，可以代理 —— 但它**返回 `com.baidu.netdisk.transfer.base.Processor`，而那是个
抽象类**（`public Processor()` + 一个抽象方法 `_()`）。

- `java.lang.reflect.Proxy` **只能代理接口**，覆盖不了类；
- 运行时造子类需要自己生成字节码，代价远超收益。

`TaskResultReceiver` 同理不能凭空造：它 `extends WeakRefResultReceiver extends android.os.ResultReceiver`，
全部意义在于被我们并不拥有的机制回调。（它的构造是 `public TaskResultReceiver(Object, Handler)`，
所以能 new，但那只是把回调指向别处，仍然不会产生字节。）

**结论：这些对象要"借"，不能"造"。** 真实下载发生时 App 会自己产出 factory / receiver /
manager 实例，模块留住它们、之后用它们发起自己的下载。这正是 `Channel` 的设计：
**观察一次，之后重放**。

为此 `Channel` 与本模块原有的 `hookDownloadPipeline` 有两点刻意不同：

1. 旧钩子把原始调用按 `MAX_CHANNEL_LOGS = 400` 截断，而 App 在真正下载前会先打几百条无关的
   `[dl]`（构造、`i() -> 0`、`m() -> false`），**恰恰把有用的那条挤掉**。新钩子按
   **签名**（声明类 + 方法名 + 参数类型）去重，签名首次出现即记录，量就压不住它。
2. 旧钩子只渲染参数；新钩子还**保留** `IDownloadProcessorFactory` / `TaskResultReceiver` /
   `CloudFile` / `Activity` 的活引用。保留本身就是目的。

### 11.4 保险库 oracle（离线，已逐字节验证）

密码 **`f_EqfhYmWxAMq!!dmL_3` 确认正确** —— 不是靠"能解开"这种间接证据，而是手工重做
scrypt + 两次 AES-KW 解包 + 校验 `versionMac`，逐字节吻合：

```
versionMac = HMAC-SHA256(hmacMasterKey, version 的 4 字节大端)   # version = 999
```

顺带确认的 spec 细节（`D:/cryptomator/baidu`，format 8 / SIV_GCM / shorteningThreshold 220）：

| 项 | 值 |
|---|---|
| scrypt | salt 8 B，cost 32768，blockSize 8，dkLen 32 |
| `primaryMasterKey` / `hmacMasterKey` | 各 AES-KW 包裹 40 B → 明文 32 B |
| **pepper** | **必须是空数组**（见下） |
| 明文根 `/` 的密文位置 | **`d/SY/RGEQKQVHFPTPFOF65L6I62FLLYWDS7`**，不是 `d/` |
| 明文文件 | 只有 1 个：`欢迎.rtf`，820 B，sha256 `141d1df78e8bb95ce053bbbae0d030be7f4a4aaadda250bc938cdc659c2dc5ac` |
| 它的密文 | `d/SY/RGEQ…/kymd3lVEAXDmA07lgpuoDiebhu6fvHpvkCQ=.c9r`，916 B |
| `dirid.c9r` | 96 B，**没有明文对应物**（是目录自身的标记） |

云端 `/crypto/content` 的列表与本机目录**逐项尺寸吻合**，所以这个本机副本就是设备上那个保险库的
等价物，可以直接当比对基准。

⚠️ **保险库几乎是空的**（1 目录 1 文件）。P2 要验证中文名 / 超长名 / 多级目录 / >32 KiB
多 chunk，这个保险库**覆盖不到**，需要先补内容（原 P0-D）。

#### 陷阱：`MasterkeyFileAccess` 的第一个参数是 pepper，不是版本号

```
MasterkeyFileAccess(byte[] pepper, SecureRandom)   // 字段名就叫 pepper
scrypt(CharSequence passphrase, byte[] scryptSalt, byte[] pepper, int cost, int blockSize)
```

传非空数组会改变 KEK，于是 AES-KW 解包失败，**抛出 `InvalidPassphraseException` —— 与
"密码真的错了" 完全无法区分**，且没有任何参数错误的提示。这一条白白吃掉了一小时
（我先后传了 `vault.cryptomator` 的内容、`masterkey.cryptomator` 的内容）。
`readAllegedVaultVersion(byte[])` 是**无关的**静态helper，它读的是*masterkey 文件自己*的
`version` 字段。

配套的两个 cryptofs 用法陷阱：

- `CryptoFileSystemProvider.newFileSystem` 要的是**保险库根目录**，不是 `d/`
  （它自己去读 `<vault>/vault.cryptomator`，再下到 `<vault>/d`）。
- 明文根是 `fs.getPath("/")`，**不是 `fs.getPathToVault()`** —— 后者回答的是"保险库存在哪"，
  返回的是**默认文件系统**上的路径，walk 它会 walk 到原始密文目录。

复现工具已入库：`tools/oracle/`（`oracle.sh check|unlock`），
`tools/oracle/README.md` 记了这两个陷阱。

### 11.5 阻塞点：下载需要存储权限（已解决）

真实触发一次下载（`/crypto/content` → 多选 `vault.cryptomator` → 底部栏「下载」）时，
App 弹出：

```
申请存储权限
用于提供文件传输功能，允许权限后您可以正常使用。
[允许]  [不允许]
```

**未授权之前不会发生任何下载**，`[ch#new]` 一条都不会有 —— 也就借不到 factory/receiver。
（是否授予该权限由用户决定；用户于 2026-10-08 08:58 授权后，同日 09:20 验证通过，见 §11.7。）

授权后顺带得到一个**独立于捕获层**的事实，它比捕获本身更省事：

> **App 的下载落点是确定性的**：`/storage/emulated/0/Download/BaiduNetdisk/<云端相对路径>`。
> 2026-10-08 用户下载的三个文件，`adb pull` 回来与本机桌面版副本 **sha256 完全相同**：

| 文件 | 大小 | sha256（两端一致） |
|---|---|---|
| `vault.cryptomator` | 283 B | `5b8dd1226a37cc8f776896ade6fde94d6a017a67b11db7e8af9ef2c729c0291a` |
| `masterkey.cryptomator` | 329 B | `45d625f66a9989752b682a4b2d421d313fa1277b34e76773212664746b72aa52` |
| `重要.rtf` | 1296 B | `3d8214e2176b7c671669bb1e8b2756a8d1660aef1c3e0f3fb94e4218a9337e38` |

这条路径是 **P3（下载自动解密）** 的天然接口：密文已经躺在本地了，模块只需要在下载完成后
就地解密覆盖，不必自己再造一条下载通道。

### 11.6 操作事实（这一轮踩到的）

- **探针只在 App 处于前台时有效。** 进程还活着（`pidof` 有值）但已被 Android 16 冻结时，
  广播收不到、什么都不记录。症状是"探针突然没反应"，`am start` 拉回前台即恢复。
- **`adb shell` 会把 `$` 当变量展开**：`--es cls 'a.b.C$D'` 到了设备侧变成 `a.b.C`，
  于是 `dump Processor$OnAddTaskListener` 静默地 dump 了 `Processor`。值里的 `$` 要写成 `\$`。
- **MSYS 路径改写在 P0-B 里有一半是反的**：Git Bash 下 `/sdcard/ui.xml` 会被改写成 Windows 路径，
  于是 `uiautomator dump` 写到了本地一个不存在的目录、`adb shell cat` 什么都读不到。
  这类参数要带 `MSYS_NO_PATHCONV=1`。反过来，`javac`/`aapt2` 这类原生 exe 又**必须**给
  `C:/…` 形式（`cygpath -m`）。
- **带空格的广播参数会在设备侧被再切一次**：`--es arg "go 18"` 到了设备变成 `--es arg go 18`，
  探针只收到 `go`。所以命令参数**不留空格**（`ch go18`），在 `Channel.command` 里按
  `startsWith("go")` 解析。
- **`su -c '… "a\|b" …'` 里的交替会被吃掉**：嵌套引号下 grep 的 `\|` 时灵时不灵，
  浪费过两轮。改成**把日志 `cat` 回本地再 grep**（3 MB，一秒），从此不在远端做正则。
- **toybox `ls` 没有 `--time-style`**，`find -newermt` 也不可靠；判断"文件是不是新的"直接看
  `ls -la` 的 mtime。
- **`input` 没有 longpress**：长按 = 起点终点同一像素的 `input swipe x y x y 900`。
  `tools/ui.py long <regex>` 即此。
- 多选底部栏的「下载」按钮与列表行里的「已下载」**共享子串**，正则必须锚定（`^下载$`），
  否则会点到「已下载」那三个字的行上。

### 11.7 P0-B 完成：观察一次、之后重放（`0.10.1-p0b2`，2026-10-08 09:20）

#### 结论

模块能**自己**把云端文件的字节拿到手。验证方式是取两个**从未下载过**的保险库密文文件，
让模块自行触发下载，再与桌面版逐字节比对：

| 文件 | 大小 | sha256（模块自行取得 vs 桌面真值） |
|---|---|---|
| `d/SY/RGEQ…/dirid.c9r` | 96 B | `c09b7632fa9e5849d729b2f4a601f6037151c2ad610cf2a4111b6bd1720fcc43` |
| `d/SY/RGEQ…/kymd3…pQ=.c9r` | 916 B | `30b1fb2b5a7ccd576030d51ac35c26d2d5cba21cb5f0671103106f699db9ab51` |

两个文件均 `cmp` 报 **IDENTICAL**。落点是
`/storage/emulated/0/Download/BaiduNetdisk/crypto/content/d/…`（即 §11.5 的确定性路径）。

#### 让捕获真正生效的两个 bug（都是"名字当类型用"）

`0.10.0-p0b` 在 08:58 那次真实下载里**看见了 37 个不同签名**，却仍然报
`factory = null / receiver = null`。原因不是观察失败，是**识别方式错了**：

```java
// 0.10.0-p0b —— 永远不可能命中
String cn = a.getClass().getName();
if (cn.endsWith("IDownloadProcessorFactory")) { ... }
```

R8 会把类搬到混淆的顶层包里。运行时的真实身份是：

```
factory  : no0.___
             implements com.baidu.netdisk.transfer.task.IDownloadProcessorFactory
receiver : com.baidu.netdisk.file.download.component.apis.FDDownloadManagerApi$addDownloadListTaskReality$newReceiver$1
             extends    com.baidu.netdisk.transfer.task.TaskResultReceiver
             extends    com.baidu.netdisk.kernel.android.ext.WeakRefResultReceiver
             extends    android.os.ResultReceiver
```

**名字在 R8 构建里不是证据，类型图才是。** `0.10.1-p0b2` 改为沿继承链 + 接口图递归匹配
（`Channel.isA`），`ch hier` 就是用来把这张图打出来的。

第二个 bug：`retain()` 只遍历 `p.args`，**从不看 `p.thisObject` 与返回值**。而
- `api`（`FDDownloadManagerApi`）只在构造时以 `this` 出现；
- `factory` 是 `FDDownloadManagerApi.q(...)` 的**返回值**。

补上之后 `manager` / `api` / `activity` / `factory` / `receiver` 五项全部到手。

#### 顺带修掉的两个真实缺陷

- **`CloudFile.readFromCursor` 崩溃**：日志里 `hook body failed … ConcurrentModificationException`。
  根因是 `noteFile()` 用 for-each 遍历 `Collections.synchronizedList` —— 行绑定在**主线程与
  binder 线程**上并发发生，迭代器不带锁。改为 `files.contains(o)`（同步的**方法**调用）。
- **报告被截断**：LSPosed 把单条多行记录截到 ~7.6 KB，第一次 `ch last` 的 37 条签名清单
  尾巴就是这么丢的。现在正文超 400 字符就落盘 `ch.txt`，日志只留指针。

#### 重放的实际形态

`ch go <n|name>` 在**主线程**上跑（`FDDownloadManagerApi.g` 收 `Activity`，有权碰 UI；
入队本身很便宜），按 App 自己出现过的调用链逐个尝试并汇报每一步结果：

```
DownloadTaskManager.d  ← App 自己在 08:58 调的就是它
DownloadTaskManager.e / .f
FDDownloadManagerApi.g / .______ / .c
```

成功判据**不是**"没抛异常"，而是**目标路径上真的出现了那个文件** ——
`manager.d` 返回 null 也可能只是被去重跳过（已下载过的文件就是这种情况，见下）。

#### 探针命令（现役）

```bash
tools/probe.sh ch last    # 捕获总览 + 全部去重签名
tools/probe.sh ch files   # 被 hold 住的 CloudFile（重放的输入）
tools/probe.sh ch hier    # 每个捕获对象的类型图 —— 读 R8 混淆类的唯一手段
tools/probe.sh ch go28    # 重放下载第 28 个（无空格，见 11.6）
```

UI 侧用 `tools/ui.py`（`dump` / `find <regex>` / `tap <regex>` / `long <regex>` / `tapxy` / `back`），
它每次 `uiautomator dump` 现取坐标再点 —— 本项目早期凭记忆点 `84,72` 点错过一次。

`tools/probe.sh` 取代了早期的 `probe.sh`：后者从行号标记 tail，曾整段丢过回复；
且它的 `sed` 只保留带 `BDCrypto:` 前缀的行 → **多行报告的正文本就是没有前缀的那部分**，
于是正文全被吃掉。`tools/probe.sh` 每次都重读整个日志并按行剥前缀。

#### 仍然存在的限制

- 重放**依赖先观察过一次真实下载**。目前 `api` 实例只在下过一次东西之后才被持有；
  下一步可以做的是反射 `new FDDownloadManagerApi()` + `api.q(list, flag, null, null)`
  自行造工厂，从而彻底摆脱"第一次必须由人手点"。
- `ch go` 一次只下一个文件，且**必须等它落盘**才能读。P2 要读的元数据文件（`dir.c9r` 等）
  都很小，代价可接受；但这条通道不适合流式解密，P3 应走 §11.5 的就地解密路径。

### 11.8 顺带发现：自带的类索引有个会骗人的盲点

`module/assets/app_classes.txt.gz` 由 `module/tools/gen_class_index.py` 从**出厂 dex** 生成，
原先硬编码只收 `com/baidu/netdisk/` 前缀 —— 于是 **R8 搬走的混淆类一个都不在里面**。
`classes no0` 查不到东西，而 `no0.___` 恰恰就是那个下载工厂。

出厂 dex 里实际有 **174,938** 个类描述符，旧过滤器只留下 **53,482** 个。现已改为默认收录全部
（`prefix` 可选，空 = 全收），产物 839 KB gzip，模块 APK 从 2.4 MB 涨到 2.9 MB，可以接受。

> 教训与 11.7 是同一条：**在 R8 构建里，名字不是证据**。索引按名字前缀过滤，
> 就等于系统性地过滤掉最需要查的那些类。

### 11.9 下一阶段（P2）开工状态

P0-D 的测试保险库已完成（见 §12），P2 的对照物齐了。剩下的是纯离线工作：
解锁（scrypt → AES-KW → `vault.cryptomator` 验签 → `cipherCombo`）+ 目录遍历
（`dirId` 是 UUID、`dir.c9r` 明文、`dirid.c9r` 走加密通道）+ 文件名解密。
读密文用 §11.7 的通道，读出后用 `tools/oracle` 的清单比对。

---

## 12. P0-D 测试保险库 + 保险库结构实测（2026-10-08 上午）

### 12.1 生成方式

```bash
bash tools/oracle/oracle.sh make /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
bash tools/oracle/oracle.sh unlock /d/cryptomator/p0d-fixture 'p0d-fixture-passphrase-7QzmN4vT'
```

- 位于 `D:/cryptomator/p0d-fixture`，**独立密钥 + 独立口令**（口令只保护合成数据）。
  独立是刻意的：模块若靠硬编码 `baidu` 的东西蒙对，在这里过不了。
- 明文**确定性**（由路径派生），所以两次生成的明文完全一致、清单可 diff；
  密钥与 vault id 随机，所以密文名每次不同 —— 这也是清单要"重新生成"而不是"入库"的原因。
- **8 个目录、21 个文件、1,155,600 字节明文**（`recon/p0d/fixture-manifest.txt`，
  该目录 gitignore）。
- 覆盖：中文名、空格、隐藏文件、emoji、Windows 非法字符、仅大小写不同的同名、
  **空文件**、1 MiB、32 KiB 边界两侧（32767 / 32768 / 32769）、超长文件名、超长目录名、
  同名文件在不同目录。

⚠️ 建库**没有**手搓 `vault.cryptomator`，而是走官方
`CryptoFileSystemProvider.initialize(vault, props, masterkeyUri)` —— 与桌面版同一个入口。
第一次尝试手写 masterkey + 自己 `toToken` + 自己 `mkdir` 根目录，结果是
`ContentRootMissingException`：**内容根目录必须已存在**，`newFileSystem` 不会替你建。

### 12.2 `initialize` 里藏着三个模块必须复现的事实

反汇编 `CryptoFileSystemProvider.initialize` 得到（不是推测）：

| 事实 | 证据 |
|---|---|
| **根目录的 dirId 是空字符串 `""`** | `ldc ""` → `hashDirectoryId(String)`；`new CiphertextDirectory("", contentRoot)` |
| 根内容目录 = `d/<hashDirectoryId("")[0:2]>/<hash[0:2] 之后>` | `hashDirectoryId` 结果 `substring(0,2)` + `substring(2)` 两次 `resolve` |
| `vault.cryptomator` 是 **HS256 JWT**，`kid` = masterkey URI | `config.toToken(masterkeyUri.toString(), masterkey.getEncoded())` |

**根目录不能靠"id 命名"找**：其它目录都是 id 的函数，根目录是 `hashDirectoryId("")`，
不调 cryptolib 算不出来。

`vault.cryptomator` 解开后（现有 `baidu` 那份，直接 base64url 解 JWT）：

```json
{"kid":"masterkeyfile:masterkey.cryptomator","alg":"HS256","typ":"JWT"}
{"jti":"b4389b25-022e-42aa-8087-bbb29b07e22b","format":8,"cipherCombo":"SIV_GCM","shorteningThreshold":220}
```

→ **P2 必须在解锁时读它**，`format/cipherCombo/shorteningThreshold` 三个参数都在里面，
签名密钥是 `masterkey.getEncoded()`（`VaultConfig.load` 反汇编已确认）。
别再把它当"纯 JSON" —— 纯 JSON 的是 `masterkey.cryptomator`。

### 12.3 真实磁盘布局（fixture 实测）

```
d/<hash[0:2]>/<rest>/                 某目录的内容目录，hash = hashDirectoryId(dirId)
    dirid.c9r                         该目录【自身】的 dirId，加密后
    <b64url 名>.c9r                    一个文件
    <b64url 名>.c9r/dir.c9r            一个【子目录】—— 名字带 .c9r 的目录，
                                       里面的 dir.c9r 是子目录 id 的【明文】
    <b64url 短名>.c9s/name.c9s         超长名被缩短：真名在这里
    <b64url 短名>.c9s/contents.c9r     ……且如果它本来是文件，内容也在这里
```

两条与直觉相反的实测结论：

- **dirId 是 UUID（36 字符 ASCII），不是哈希。** 实测 `dir.c9r` 内容：
  `74d5156d-183c-44d8-a6fb-f3fa1d364c46`（`xxd` 明文可读）。
  `hashDirectoryId` 只是把 id 映射成 `d/` 下那个 32 字符 base32 名。
  子目录 id 在**父目录里是明文**，被加密的是**名字**。
- **超长名会把"文件"变成"目录"**：`.c9s/` 下 `name.c9s` 存真名，
  `contents.c9r` 存内容。只认"`.c9r` 结尾即文件"的代码会整片漏掉。

旧记录里"目录布局 `d/<前2>/<余30>`（dirId 32 字符 = base32(SHA1)）"**表述不准**：
32 字符那个是 `hashDirectoryId(dirId)` 的输出，不是 dirId 本身。

### 12.4 内容文件的体积模型（5 种尺寸全部吻合）

```
磁盘字节 = 68 + 28 * ceil(明文 / 32768) + 明文
```

| 明文 | 磁盘 | 算式 |
|---|---|---|
| 0 | 68 | 68 |
| 24 | 120 | 68 + 28 + 24 |
| 32768 | 32864 | 68 + 28 + 32768 |
| 32769 | 32893 | 68 + 56 + 32769 |
| 1048576 | 1049540 | 68 + 896 + 1048576 |

每 chunk 28 字节与"12 字节 nonce + 16 字节 GCM tag"吻合；固定的 68 字节是扣掉 chunk 之后
剩下的部分。

⚠️ **`dirid.c9r` 不遵守这个模型**：空 dirId（根目录）仍是 **96** 字节 = 68 + 28，
即**空明文也写了一个 chunk**；而 0 字节的文件内容只有 68（一个 chunk 都没写）。
读 `dirid.c9r` 与读文件内容不能共用同一套"长度=0 即空"的判断。

**68 字节那段的内部结构尚未解开**（`xxd` 看是无特征的随机字节，文件之间不同）。
这属于 P3，且必须靠 cryptolib 解密来解，不能靠算术猜。

### 12.5 顺带修掉的两处记录错误

**(a) `Unlock` 把每个文件的明文 base64 全量打进清单。** fixture 带 1 MiB 文件后，
清单从 12 KB 涨到 1.5 MB、无法阅读。现改为**明文 ≤256 字节才内联**，否则只打 sha256
（大文件本来就靠摘要比对）。

**(b) `baidu` 保险库里那个文件叫 `欢迎.rtf`，不是 `重要.rtf`。** §11.4 与本文件 §11.8
原先写错，已更正。区分两件事：

| | 位置 | 大小 | 是不是保险库里的条目 |
|---|---|---|---|
| `欢迎.rtf` | 保险库内（密文 `d/SY/…/kymd3l….c9r`） | 820 B 明文 | **是**（`unlock` 解出来的真名） |
| `重要.rtf` | `D:/cryptomator/baidu/` 根下 | 1296 B 明文 | **否**，用户手工放的普通文件 |

两者大小也不同（820 vs 1296），**不是同一份文件的两个副本**。同目录下还有
`masterkey.cryptomator.bkup` / `vault.cryptomator.bkup` —— 保险库目录里出现非保险库文件
是正常的，**不能靠"目录里看到了什么"判断保险库内容**，只能靠 `d/` 下的密文树。


