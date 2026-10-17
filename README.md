# GUI for PKI and DSS

面向普通工程师的 PKI / DSS Web 工具台。应用源码位于 [`app/`](app/)，支持 Windows 本地运行，并为后续 IIS / ASP.NET Core 公网部署保留生产配置入口。

## 快速启动

```powershell
cd app
dotnet run --urls http://127.0.0.1:5080
```

浏览器打开 <http://127.0.0.1:5080/>。完整账号、供应商接口配置、数据库和公网部署说明见 [`app/README.md`](app/README.md)。

仓库只保存源码和静态资源；本地数据库、Data Protection 密钥环、mTLS 私钥、构建产物和附件工作文件均不会提交。
