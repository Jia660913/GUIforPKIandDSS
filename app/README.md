# ZF 工具台

这是面向普通工程师的 PKI / DSS Web 工具。工具账号、项目权限和操作记录由本地工具数据库维护；供应商后台账号不会发给浏览器，供应商凭据只由服务端调用接口。

## 本地启动

工作区已包含隔离的 .NET 10 SDK。PowerShell 中执行：

```powershell
cd C:\Users\15590\Documents\Codex\2026-10-17\wo
.\work\dotnet10\dotnet.exe run --project app\ZfTools.csproj --urls http://127.0.0.1:5080
```

打开 http://127.0.0.1:5080/。默认本地演示账号：

- PKI 管理员：`pki-admin` / `ChangeMe-PKI-2026!`
- DSS 管理员：`dss-admin` / `ChangeMe-DSS-2026!`

首次部署后请立即更换管理员密码；这些账号只用于本地演示。`app/zf-tools.db`、`app/.keyring` 和 mTLS 私钥不应提交到源代码仓库。

## 当前能力

- PKI：选择启用的三级模板、开发/量产环境，填写 Variant / Unique ID，生成 Ed25519 CSR 和 PKCS#8 私钥，或上传已有 CSR。私钥不会保存到服务器。
- DSS：用户绑定一个项目，只能看到该项目的密钥。摘要输入按十六进制解码后签原始字节，字符串按 UTF-8 签名；当前供应商配置为 Ed25519 `key-sign-text`。
- 管理员：维护工具账号、激活/吊销、重置密码；DSS 管理员维护项目和密钥映射；PKI 管理员维护三级模板。
- 记录：管理员查看本工具全部记录，普通用户只能看自己的记录；PKI / DSS 申请记录和审计记录保留一年。

## 供应商接入

默认配置是本地 Mock，不会调用供应商。生产环境使用 `appsettings.Production.json`，其中 Mock 已关闭。PKI 需要供应商申请接口 HTTPS 地址和 mTLS 客户端证书；DSS 项目在 DSS 管理页维护 HTTPS 地址、appKey、appSecret 和 mTLS 客户端证书路径。appSecret 与证书密码使用 ASP.NET Data Protection 加密后写入数据库，公网部署必须持久化并保护 `app/.keyring`，多实例部署需共享同一密钥环。

供应商联调前需要确认：PKI 交付文档示例出现 `.509` 自定义 OID，而用户提供的 X.509 结构表和实际证书使用 `.589`；当前实现按结构表 `.589` 编码。还需用供应商测试端确认 CSR 扩展 critical 标志、Claims 的 ECU Unique ID 表示和 DSS 请求鉴权的完整 URL 编码细节。当前本地 Mock 已验证，真实供应商接口尚未使用真实凭据联调。

## 公网迁移要点

在 Windows 服务器上以 IIS / ASP.NET Core Module 或受控反向代理终止 HTTPS，配置固定域名、证书、数据库路径、Data Protection 密钥环和供应商 mTLS 证书目录；仅允许代理转发后的 HTTPS 请求访问应用。设置 `ASPNETCORE_ENVIRONMENT=Production`，将真实密钥放在受保护的部署配置或密钥管理系统中，不要放入 Git。
