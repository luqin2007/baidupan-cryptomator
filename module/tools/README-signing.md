# 签名与密钥

## 现状

`v0.1.0-p0` 之前的构建（含本机调试装的那一版）用的是自动生成的 **debug key**。
从 `v0.1.0-p0` 起改用正式发布密钥。

| 项 | 值 |
|---|---|
| 证书 DN | `CN=BdCryptomator, O=luqin2007, C=CN` |
| 算法 | RSA 4096 / SHA256withRSA |
| 有效期 | 10950 天（≈30 年） |
| 存储 | `module/keystore/release.keystore`（PKCS12） |
| 证书 SHA-256 | `9A:34:AD:E0:AC:34:FC:87:8B:89:AC:31:AA:16:B2:C7:6C:F8:02:3B:E7:AF:48:A2:3C:F1:03:0F:B2:1F:31:ED` |
| 证书 SHA-1 | `DD:E8:B7:04:BF:40:12:06:FB:2D:5C:A7:14:BD:84:E8:A0:A0:6B:E5` |

> ⚠️ **`module/keystore/` 与 `module/keystore.properties` 都不入库**（`.gitignore` 挡住）。
>
> **这两个文件丢了，就再也发布不出能覆盖安装的更新** —— Android 要求新版本与原版本同签名，
> 否则用户必须卸载重装（会丢掉 LSPosed 里的作用域授权）。请立刻做**离线备份**。

## 为什么现在是换密钥最好的时机

正式密钥与 debug 密钥互不兼容：装了 debug 签名的模块，再装正式签名版会报
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`。本机设备上目前装的是 debug 版，但**作用域还没勾选**，
所以现在重装一次没有任何代价；等 P1 之后功能可用了再换，就要额外付一次"重新勾选作用域"的成本。

## 使用

```bash
# 构建时脚本自动读取 keystore.properties，不需要额外参数
bash module/build.sh

# 校验
"$JAVA_HOME/bin/java" -jar "$ANDROID_HOME/build-tools/<ver>/lib/apksigner.jar" \
    verify --verbose --print-certs dist/BdCryptomator-<ver>.apk
```

`apksigner` 通过 `env:` 读密码（`KS_PASS` / `KEY_PASS`），密码不进命令行，`ps` 里看不到。

`--v1-signing-enabled true` 是刻意开的：`minSdkVersion >= 24` 时 v1 事实上不适用，
`apksigner verify` 会报 `Verified using v1 scheme: false`，这是**预期行为不是问题**；
但少数第三方 ROM 的安装器仍会看 v1。`--v4` 关掉，免得留下 `.idsig` 垃圾文件。

## 用户如何校验

```bash
apksigner verify --print-certs BdCryptomator-0.1.0-p0.apk | grep SHA-256
# 应输出上面的 SHA-256（或 SHA-1）指纹
```
