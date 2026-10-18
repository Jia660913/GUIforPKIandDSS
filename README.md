# GUI for PKI and DSS

面向普通工程师的 PKI / DSS Web 工具台。应用源码位于 [`app/`](app/)，支持 Windows 本地运行和后续 IIS / ASP.NET Core 公网部署。PKI 与 DSS 分别对接供应商现有 API；账号、权限、连接映射和一年操作记录由工具管理。

## 快速启动

```powershell
cd app
dotnet run --urls http://127.0.0.1:5080
```

浏览器打开 <http://127.0.0.1:5080/>，需要 .NET 10 SDK。完整账号、供应商接口配置、API 请求/响应、数据库和公网部署说明见 [`app/README.md`](app/README.md)。

默认关闭 Mock。只有管理员配置好对应环境的 mTLS、业务映射及已确认的协议规则后才允许真实调用；缺少接入材料时明确显示未配置，不产生模拟签发或签名结果。供应商系统无需改动。

从仓库根目录运行 `dotnet run --project tests/ZfTools.Tests.csproj` 执行本地检查，包含隔离的 HTTPS/mTLS 测试端点，不连接供应商。

仓库只保存源码和静态资源；本地数据库、Data Protection 密钥环、mTLS 私钥、构建产物和附件工作文件均不会提交。
