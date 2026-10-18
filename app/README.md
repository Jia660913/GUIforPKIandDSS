# ZF PKI / DSS 工具台

面向普通工程师的 ASP.NET Core 10 / Razor Pages Web 工具，界面使用英文、Arial 和 ZF 蓝色风格。工具独立维护账号、权限和操作记录，通过现有 API 调用供应商系统，不创建或修改供应商的项目、密钥、CA 模板或后台账号。

当前默认关闭 Mock。未配置完整的连接和业务映射时，页面显示缺少的配置并阻止实际申请或签名，不会返回模拟成功结果。代码和本地测试端的验证不能替代供应商真实环境联调。

## 本地启动与检查

安装 .NET 10 SDK 后，在仓库根目录执行：

```powershell
dotnet run --project app/ZfTools.csproj --urls http://127.0.0.1:5080
```

当前工作区也有隔离 SDK，可将 `dotnet` 换为 `.\work\dotnet10\dotnet.exe`。这个 SDK 位于忽略目录，不随 Git 仓库交付。打开 <http://127.0.0.1:5080/>。

全新数据库首次初始化时创建以下本地管理员；现有数据库的账号和密码不会被重置：

| 工具 | 账号 | 初始密码 |
| --- | --- | --- |
| PKI | `pki-admin` | `ZfPki-Tool-2026!` |
| DSS | `dss-admin` | `ZfDss-Tool-2026!` |

公网部署前应通过账号页面更换这些公开的初始密码。新增和管理员重置密码的账号按工具规则执行首次改密。

从仓库根目录构建并运行测试：

```powershell
dotnet build app/ZfTools.csproj
dotnet run --project tests/ZfTools.Tests.csproj
```

测试是独立的可执行检查程序，包括 CSR/证书规则、DSS 编码与鉴权、权限和历史记录、旧数据库升级，以及本机 HTTPS/mTLS 测试服务的请求与响应检查。它使用临时测试材料，不调用真实供应商端点。

## 普通用户工作流

**PKI**：选择 Development / dev 或 Production / field，再选择启用的三级证书模板。填写 Common Name、ECU Variant ID 和按角色要求的 ECU Unique ID，生成并预览 CSR；或者上传已有 PEM CSR，让工具读取这些字段。生成方式产生 Ed25519 密钥，用户下载 PKCS#8 私钥并确认已保存后才能申请。私钥在服务端内存中生成并通过当前页面交付，不写入数据库或文件，也不随申请表单重新提交；页面禁止缓存。上传方式只接受公开 CSR。

申请前再次验证 CSR 自签名、公钥算法、字段、类型和模板规则。申请成功后验证返回证书的公钥、ECU 标识、角色、信任级别、有效期和三级签发链，再提供 PEM 证书下载。PKI 账号不绑定项目，能够使用所有已启用并配置好的三级模板。

**DSS**：普通用户只能使用管理员分配项目下、所选环境中的已登记密钥；管理员可选择已配置的有效项目，不默认绑定或选中某个项目。密钥算法、状态和公钥通过现有 `key-get` 接口读取，页面可刷新所选密钥，实际签名前也会再次读取供应商当前元数据。当前仅启用有效的非对称 Ed25519 密钥，算法随所选密钥确定。摘要输入必须是偶数长度的十六进制，不接受空格或 `0x`；解码后的原始字节被签名。字符串按 UTF-8 字节签名。工具不会再次哈希后再签名，历史中的 SHA-256 仅用于审计。输出是独立的 64 字节签名，以 128 个十六进制字符显示和下载。当前流程不上传或保存原始软件包。

工具后端重新查询账号、项目、环境、密钥和连接的关联，不依赖浏览器筛选保证权限。两个工具的账号、管理入口和历史记录相互隔离。

## 管理员配置

各工具的 Administration 页面分别维护连接和映射。连接必须指向供应商 HTTPS **origin**，例如 `https://zf.easysec.com.cn:10001`，不能包含 API 路径、查询参数或用户名密码。文件路径为工具服务器上的绝对路径。

配置顺序是：保存连接草稿 → 填齐接入材料并启用连接 → 保存现有供应商对象的映射 → 确认规则并启用映射。未完成的条目可保留为禁用草稿。这里的保存只写工具数据库，不会在供应商系统里创建对象。供应商文档未提供模板、项目和密钥的列表 API，所以映射由管理员维护。

### PKI 连接与三级模板

每个环境配置独立的 PKI 连接，可在供应商现有部署允许时使用相同 origin：

- 客户端 PEM 证书和 PEM 私钥，或包含一个私钥身份的 PFX；如有加密，填写密码。
- 可选客户端中间 CA 链；也可随 PEM/PFX 提供。
- 供应商 HTTPS 服务端 CA 信任包，PEM 格式，包含信任根和需要的中间证书。
- 业务证书的根 CA / 二级 CA PEM 包，用于验证返回的三级证书。它与 HTTPS 服务端信任包是两个独立配置。
- 请求超时，1–300 秒，默认 30 秒。

三级模板映射需要填写供应商已存在的**精确 `cert_profile`**、环境、角色、连接，以及已确认的 CSR 规则。全新数据库仅预置 11 个角色 × 2 个环境的 22 条禁用草稿，不猜测 `cert_profile`。管理页面按 Development 和 Production / field 分组展示映射，诊断角色数为 11，不把环境副本计作新增角色。原来 3 条未连接供应商的演示模板会归档，不再出现在申请或配置列表中；已有记录引用仍保留。

| 角色 | Role Hex | 有效期（天） | ECU Unique ID |
| --- | --- | ---: | --- |
| OEM Development | `00800000` | 30 | 必填 |
| OEM Production | `00400000` | 180 | 可选 |
| OEM Field Basic | `00100000` | 14 | 可选 |
| OEM Field Standard | `00080000` | 7 | 可选 |
| OEM Field Enhanced | `00040000` | 3 | 可选 |
| ZF Development | `00000080` | 30 | 必填 |
| ZF Production | `00000040` | 180 | 可选 |
| ZF Field Basic | `00000010` | 14 | 可选 |
| ZF Field Standard | `00000008` | 7 | 可选 |
| ZF Field Enhanced | `00000004` | 3 | 可选 |
| ZF Claims | `00000002` | 30 | 必填 |

OEM Claims 为预留角色，不开放申请。角色名中的 Development / Production 与连接选择的 dev / field 是两个维度，不能用其中一个代替另一个。

业务扩展按已确认的 `.589` 结构编码：

| 扩展 | OID | ASN.1 内容 |
| --- | --- | --- |
| CertType | `1.3.6.1.4.1.13159.1.2.589.3.1.1` | OCTET STRING，`diagUser` |
| TrustGrade | `1.3.6.1.4.1.13159.1.2.589.3.2.1` | OCTET STRING，`dev` / `field` |
| DiagUserRole | `1.3.6.1.4.1.13159.1.2.589.3.3.1` | INTEGER |
| ECUVariantID | `1.3.6.1.4.1.13159.1.2.589.3.4.1` | OCTET STRING，Hex 解码字节 |
| ECUUniqueID | `1.3.6.1.4.1.13159.1.2.589.3.5.1` | UTF8String |

CertType / TrustGrade / Role 由 CA 模板固定。默认不要求它们出现在 CSR；若供应商现有配置要求，可勾选生成时包含固定字段。已包含的固定字段必须匹配所选模板。Variant 默认允许 1–16 字节，也可配置精确长度；Unique 最多 32 个 UTF-8 字节。Common Name 最多 256 个 UTF-8 字节。可配置已确认的 CN / Unique 格式正则、扩展 critical 标志、额外扩展的拒绝/接受策略。额外扩展的接受策略只代表跳过工具对此类扩展的拒绝，不能保证 CA 会将其写入证书。

必须按供应商**已有模板**确认这些参数及无需人工审批的即时签发行为，然后勾选 CSR policy confirmed。工具不会通过更改供应商配置满足条件。

### DSS 连接、项目与密钥

每个 DSS 连接绑定工具项目及环境，填写该供应商项目获授权的 mTLS 身份、服务端信任包、`appKey`、`appSecret`、超时和输入上限。PKI 的接入材料不能自动当作 DSS 凭据。

项目在工具中是账号访问分组，不会在供应商系统创建项目。密钥登记填写已有授权项目下精确的 `keyName`、环境和连接。保存登记后，使用 **Refresh from supplier** 调用 `key-get`，读取算法、曲线、类型、状态、长度和公开公钥，并显示刷新时间；算法和公钥不再手工填写。新登记或变更密钥身份时，旧元数据清空，完成刷新前不假定算法为 Ed25519。正常签名流程使用读取到的 Ed25519 公钥在本地验证返回签名。

`key-get` 只能查询已知的精确密钥名，不能列出或发现项目和密钥。供应商新增项目或密钥后，管理员仍需在工具中登记访问分组、连接和密钥名；已登记密钥的属性可以刷新，并在每次真实签名前重新获取。读取或刷新失败会阻止该次签名，不沿用旧元数据继续发送签名请求。工具不调用供应商项目、密钥的创建、修改或删除操作；若响应含有业务私钥或对称密钥字段，工具会丢弃，不保存或向浏览器交付。

供应商文档没有明确响应鉴权的完整拼接规则，因此实际发送前还必须配置并确认响应签名规则。支持 SHA-256、`java-form` 或 `utf8` 编码，模板可使用 `{method}`、`{path}`、`{requestNonce}`、`{requestTimestamp}`、`{responseNonce}`、`{responseTimestamp}`、`{appKey}`、`{body}`、`{appSecret}`。模板至少包含 `{body}` 和 `{appSecret}`，分隔符和顺序必须与供应商提供的规则完全一致；不能把测试模板当作供应商规则。若实际规则不属于这一可配置格式，需要适配工具代码，不能通过关闭响应校验继续使用。

证书密码和 `appSecret` 经 ASP.NET Data Protection 加密后写入数据库，不在页面回显。密码输入留空会保留已保存的值；切换为无密码身份时，使用明确的 Clear saved password 复选框。

### 输入大小

`Dss:MaxInputBytes` 默认为 1 MiB，连接的 Maximum decoded input 也默认 1 MiB；实际限制取两者较小值，且连接设置最多 16 MiB。提升限制时需同时修改全局配置和连接配置，并遵守供应商已确认的上限。这里按解码后的摘要字节或 UTF-8 字节计算。

Kestrel 请求体上限为 64 MiB，表单单值上限为 48 MiB。公网代理/IIS 还需独立配置请求体上限；表单编码可能膨胀，不能将请求体上限直接当作签名数据大小。CSR 最大为 128 KiB。

## API 实际传输

### PKI

文档测试 origin 为 `https://zf.easysec.com.cn:10001`。工具通过 PKI mTLS 身份调用 `POST /esca/api/v1/cert/apply`，不使用供应商管理后台账号密码，也不添加 DSS 的 app 鉴权头。

```json
{
  "requestParams": {
    "cert_profile": "<existing supplier profile>",
    "csr": "<Base64 of the complete public CSR PEM>"
  },
  "requestMetadata": {
    "requestID": "<tool-generated correlation ID>",
    "userSourceIP": "<request IPv4 address>",
    "ecuVariant": "<Hex value parsed from the verified CSR>"
  }
}
```

要求响应有 `code: "000000"`、`data.requestId` 和 `data.certificate`；后者是完整 PEM 证书的 Base64。私钥不出现在 API 请求中。返回内容通过业务校验后才记为成功。

### DSS

文档测试 origin 为 `https://zf.easysec.com.cn:18100`。工具用 DSS 自己的 mTLS 身份先调用 `POST /api/kms/v4/key-get`，查询已登记的密钥：

```json
{"keyName":"<existing supplier key>"}
```

响应鉴权通过后，工具核对返回的 `keyName`，读取 `keyAlgorithm`、`encrycurve`、`keyType`、`keyStatus`、`keyLength` 和十六进制 DER `publicKey`。`EdDSA` / `Ed25519` 规范化为签名算法 `Ed25519`；只有 `keyStatus: "1"`、`keyType: "asymmetric"` 且公钥匹配的 Ed25519 密钥才允许进入当前签名流程。其他算法的元数据可读取，但不会因此开放其签名能力。响应中的其他密钥材料不被持久化或展示。

随后调用 `POST /api/kms/v4/key-sign-text`：

```json
{"keyName":"<existing supplier key>","signAlgorithm":"Ed25519","data":"<Hex of bytes to sign>"}
```

请求带 `es-auth-appkey`、随机 `es-auth-nonce`、毫秒 Unix 时间戳 `es-auth-timestamp` 和 `es-auth-sign`。签名串为以下内容的直接拼接，不加入换行或额外分隔符：

```text
POST + path + es-auth-appkey: + appKey + es-auth-nonce: + nonce + es-auth-timestamp: + timestamp + json= + exactJsonBody + appSecret
```

对整个拼接串做 Java `URLEncoder` 等效的 UTF-8 form 编码，再做 SHA-256，输出小写 Hex。这不是 HMAC。请求鉴权规则与可配置的响应鉴权规则分别处理。

以上两个接口使用相同的请求鉴权及已确认的响应鉴权规则。签名响应必须先通过 appKey 和 `es-auth-sign` 校验，再读取 `signData`。签名必须为 64 字节 Hex，并使用本次 `key-get` 读取的公钥对原始输入字节完成本地 Ed25519 验签，才显示成功。正常调用顺序为 **`key-get` → `key-sign-text` → 本地 Ed25519 验签**；缺少有效公开公钥时不会跳过元数据检查进入签名。该流程不会更改供应商项目、密钥或其算法配置。

## 历史记录与故障处理

管理员可查看本工具所有用户记录，普通用户只能查看自己的记录，每页 25 条。记录包含操作时的模板、角色、项目、环境、密钥和连接名称快照，后续修改映射不会改写原操作含义。

PKI 保存 CSR 的 SHA-256、解析的业务字段、请求 ID、返回证书和状态，不保存私钥。DSS 保存原始输入的文本表示、输入字节的 SHA-256、收到的签名、响应鉴权和验签状态。即使收到签名后的验证失败或中断，也保留已收到的签名用于排查；只有已验证成功的结果可从下载入口获取。

`pending` 表示处理中；`succeeded` 表示结果已校验；`failed` 表示拒绝或已确认的失败；`unknown` 表示请求可能已经被供应商处理，但工具无法确认最终结果。连接中断、超时等不会自动重试。管理员应使用请求 ID 或供应商日志核对后再决定重新提交。启动时及每天的清理任务会将超过 15 分钟的遗留 `pending` 标为 `unknown`。

记录和审计数据保留一年；列表、详情和下载均执行保留期限制，后台每日删除过期数据。旧演示结果标为 `demo`，其他未验证旧记录标为 `legacy`，不会当作真实供应商成功结果。启动时还会归档精确匹配原始未连接演示配置的 PKI 模板和 DSS 密钥（包括 `abs-debug-ed25519`）；归档项不再可选，数据库 ID 和历史记录仍保留。全新数据库不再创建虚构的供应商密钥。

## Windows / 公网迁移

数据库升级是应用启动时执行的可重复增量升级，保留现有账号、配置和记录。升级前应备份数据库；不要为了初始化新配置删除已有数据库。

后续部署需要迁移：应用发布文件、SQLite 数据库、Data Protection 密钥环、供应商 PEM/PFX 与信任链文件，以及服务器配置。证书路径在新服务器重新映射，文件权限授予应用运行账号。数据库和密钥环必须配套保留，否则已有供应商密码和 `appSecret` 无法解密。配置键如下：

| 配置键 | 用途 / 默认值 |
| --- | --- |
| `ConnectionStrings:Default` | `Data Source=zf-tools.db`；公网建议使用绝对数据库路径 |
| `DataProtection:KeyRingPath` | 默认为应用内容目录下 `.keyring` |
| `Dss:MaxInputBytes` | 全局签名输入上限，默认 `1048576` |
| `Suppliers:Pki:UseMock` / `Suppliers:Dss:UseMock` | 默认均为 `false` |
| `ReverseProxy:Enabled` | 默认 `false` |
| `ReverseProxy:KnownProxies` | 启用代理时必须配置至少一个受信任代理 IP |
| `AllowedHosts` | 部署时改为实际域名 |

环境变量覆盖配置时用双下划线，例如 `ConnectionStrings__Default`、`DataProtection__KeyRingPath`。Data Protection ApplicationName 固定为 `ZfEngineeringTools`，迁移时保持一致。数据库、密钥环和证书私钥不属于源码交付物；部署目录和备份需限制访问。持久化密钥环本身未在此项目中启用额外的静态加密，应按部署环境保护存储。

Windows 可通过 IIS / ASP.NET Core Hosting Bundle 或受控反向代理提供公网 HTTPS。设置 `ASPNETCORE_ENVIRONMENT=Production`，配置域名、HTTPS 证书和反向代理信任地址。PKI API 要求 `userSourceIP` 为 IPv4；当前工具拒绝用 IPv6 源地址发起申请，需要在现有入口设计中明确可传递的 IPv4 来源。不要伪造来源或信任任意客户端提交的转发头。

供应商 HTTPS 验证检查配置的信任链、有效期、serverAuth EKU 和主机名，不关闭证书校验、不跟随重定向。当前尚无供应商 CRL/OCSP 策略，未实施在线吊销状态检查；启用真实部署前需明确这一运维要求。工具默认只连接管理员配置的服务器，不要求更改供应商系统。

## 真实联调仍需的输入

- 两个系统分别适用的客户端身份、私钥、密码和 CA 链，以及测试端现有访问授权；不能仅凭网页可登录推断 API 已获授权。
- PKI dev / field 的精确 `cert_profile` 清单、对应角色、现有 CSR 参数、即时签发规则，以及用于验证返回证书的业务 CA 链。
- DSS 各项目 / 环境精确的 `keyName`、对应 `appKey` / `appSecret`、响应鉴权完整规则与样例，以及现有身份访问 `key-get` / `key-sign-text` 的授权；公开公钥由 `key-get` 读取。
- 已确认的输入大小、超时、网络 / VPN / IP 白名单和源地址条件。

这些是现有系统的接入材料和配置事实。工具不会要求供应商添加 API、修改业务流程或改造后台。
