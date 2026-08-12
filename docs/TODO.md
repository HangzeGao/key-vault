# TODO

### Service-separated production policy

- [x] 默认与签名策略允许 CTR 仅加密、CMAC 仅认证和 GCM 加密认证的 AES/SM4 套件。
  - Key purpose 与 suite service type 强绑定；`AUTH_ONLY`/`ENCRYPT_ONLY`/`AUTH_ENCRYPT` 分别只允许 CMAC/CTR/GCM；ECB 不能通过策略语义校验，也不再出现在前端选择器中。
  - CMAC 使用独立 Authenticate/Verify API、分离标签和常量时间校验；CTR 明确拒绝 AAD。
  - 解密时 Envelope suite 必须与 Key suite 和 Envelope 记录的历史策略版本完全一致。
- [x] Encrypt 要求显式 Key。
  - 未提供 `tenant_id` 时使用 principal tenant；未提供 `key_id` 时返回 `INVALID_ARGUMENT`，不隐式创建默认 Key。
  - Decrypt 请求体直接使用 Envelope JSON；Key、KeyVersion 和 suite 从 Envelope 中解析；不支持仅凭 raw ciphertext 推断默认 KeyVersion。

更新时间：2026-07-28

当前工程基线已完成本轮上线前安全默认值与信任链改造。下方保留既有完成记录；真实生产发布仍以 `baseline/docs/PRODUCTION_SECURITY.md` 的阻塞项为准。

## 生产发布阻塞项

- [ ] 按 `baseline/docs/CRYPTOGRAPHIC_TEST_DESIGN.md` 补齐密码算法 P0 验证：GB/T/GM/T SM4 单分组 KAT、RFC 8998 SM4-GCM KAT、OpenSSL 独立差分、无共享实现的 HCTR 参考模型、ASan/UBSan 与有界 fuzz、星载启动 KAT 及失败锁定。
- [ ] 完成密码实现 P1/发布加固：可复现 bit-flip campaign、目标板 WCET/栈/代码尺寸、实际飞行编译器交叉验证、目标 CPU timing leakage，以及威胁模型要求时的功耗/电磁 TVLA。
- [ ] 冻结任务级 TC `VCID -> APID -> 指令码` 映射、各指令精确长度、参数范围、保留位、填充、包内校验和与正反样例；通用必选合同与发布门禁已固化在 `baseline/docs/TC_PLAINTEXT_VALIDATION_DESIGN.md`，ADR 0005 仅记录线协议决策。
- [ ] 使用任务选定的 CCSDS 355.0-B-2 profile 与权威互操作向量验收 TC 保护、AOS 解保护、帧边界、截断字段及 SA rollover。
- [ ] 增加 CCSDS Security Association 的受控管理面、双人审批、审计与应急防重放状态重置流程。
- [ ] 将 Key Plane 作为独立部署边界，通过 mTLS RPC 向公共平面提供最小能力。
- [ ] 实现 KeyVersion 全量原子重封装、租约失效与回滚安全的 CRK 轮换。
- [ ] 实现按 `(node, plane)` TPM 身份的注册与 CRK Envelope 分发。
- [ ] 在 CI/预生产完成 PostgreSQL PITR、native TPM、JWKS 轮换和三平面部署演练。
- [ ] 在干净且联网的 CI runner 中按 `package-lock.json` 完成前端构建与测试。

## 完成状态

### CCSDS 链路安全最小内核

- [x] 建立不输出 Envelope 的原始保护核心，并保持 `AUTH_ONLY -> CMAC`、`ENCRYPT_ONLY -> CTR`、`AUTH_ENCRYPT -> GCM` 闭合集合。
- [x] 将普通 TC profile 收敛为 `主导头5B + SPI2B + IV_COUNTER4B + SM4-HCTR密文 + FECF2B`，无 Tag，不保留 CTR/AES 或数据域返回兼容格式。
- [x] 增加星上 C11 SM4-HCTR 接收模块，以固定内存完成帧长/FECF、SPI/SA、解密、业务校验回调和防重放状态持久化顺序。
- [x] 地面 Go 完整明帧输入/完整密帧输出与星上 C 完整密帧输入形成闭环，并共用固定 TC 联调向量；普通 TC 只声明保密性，不声明认证或密码学完整性。
- [x] 以严格 Mission Security Profile 作为星地唯一配置源，一次生成 TPM 包装的地面 Root、初始星载 NVM、完整 Recovery Root Prepare 帧和哈希发布证据；拒绝未知字段、重复字段、旧参数和配置漂移。
- [x] 固化 `PREPARED -> SWITCHING -> ACTIVE` 地面轮换证据链；受控本地激活要求 reason/ticket 并审计，星上通过首帧合法 Next SPI 自动提交 Pending Root，不新增线上管理指令。
- [x] 实现星载固定格式双槽 NVM 编解码、CRC32C 及反码、Profile 摘要、单调 generation 下限、损坏新槽回退和歧义状态拒绝。
- [x] 增加统一 release gate：Go 全量测试、真实 API 到星载共享向量、地面/星载 95% 覆盖率门禁、前端测试与构建，并输出源码及向量哈希证据。
- [ ] AOS 帧格式冻结后，将解保护接口收敛为完整密帧输入、完整明帧输出，并统一处理 Security Trailer、帧长与 FECF；冻结前不固化临时线上格式。
- [x] 协议 Key 与通用数据 Key 使用域隔离；SA 固定绑定精确 KeyVersion、PolicyVersion 与 suite。
- [x] SQLite SecurityState 持久化 TC IV Counter 和 AOS 64 位滑动防重放窗口；认证失败不推进接收状态。
- [x] 暂不引入 Protocol Registry、插件生命周期或通用帧 DSL，仅保留原始保护接口作为未来第二协议的扩展缝。

### P0 · 安全边界与生产化

- [x] 完成 Ops Plane 高危动作统一治理。
  - `repair-aad-digest`、resolver refresh、lifecycle retry、outbox replay 统一要求 `reason`、`ticket_id`、`Idempotency-Key`。
  - 统一记录 target/current state/impact/rollback/expected result preflight，审计链形成 `requested -> succeeded|failed|aborted` 配对。
  - 审计或幂等预留不可用时 fail-closed；响应只返回 ticket、状态、preflight 和脱敏摘要。
- [x] 实现独立 `ops:breakglass` 流程。
  - 独立 URL 前缀与 scope；额外要求 `impact_scope` 和 `operator_confirmation`。
  - 白名单只覆盖既有修复动作，不存在任意 SQL、shell、脚本、备份/密钥导出和直接 purge。
  - 已覆盖缺 reason/ticket/幂等键、缺强确认、审计失败及 plane/scope 越权负向测试。
- [x] 实现进程内原生 TPM provider。
  - `native` / `tss` / `esapi` 使用 go-tpm，不 shell out、不依赖 PATH、不写 CRK 明文临时文件；错误 transport 启动失败。
  - 支持 TPM sealed object 持久 envelope、重启恢复、上下文错误和 envelope 损坏拒绝；vTPM 测试在支持 CGO 的测试环境运行。
  - `software`、`swtpm`、`tpm2-tools` 保留为工程 fallback，生产配置显式拒绝。
- [x] 将 CRK 上下文绑定下沉到 TPM 强制边界。
  - 配置 PCR 集通过 `PolicyPCR` 约束；`cluster_id`、`node_id`、`plane_role`、`baseline_digest`、`policy_digest` 的 canonical context 参与 TPM object authorization。
  - 设计文档明确 `crk_aad_digest` 仅为应用层完整性校验。
- [x] 补齐数据面 AAD 合约与租户策略。
  - 单条/批量统一处理未传、空、非法 base64、非空与错误 AAD；错误使用稳定码且不泄露 AEAD/Envelope 内部细节。
  - tenant envelope config 增加 `aad_required`，Encrypt/Decrypt/Batch 和前端保持一致。
- [x] 落地容量保护与限流。
  - 使用 `rate_window`、`rate_sigma_threshold`，覆盖 hot key、crypto、batch、audit、lifecycle/outbox 与 Ops 变更请求。
  - 保留 64 KiB body、100 条 batch 上限，响应增加逐项结果、成功/失败汇总和 failure ratio；限流返回 429、`Retry-After` 与剩余额度。
- [x] 加强生产部署安全门禁。
  - `environment: production` 强制 PostgreSQL、native TPM、physical plane isolation；production fingerprint 不明确时拒绝启动。
  - 审计递归脱敏覆盖 token、authorization、plaintext、DEK/CRK、wrapped material、ciphertext/envelope，同时避免误伤 `envelope_format` 等安全元数据。
  - PostgreSQL 集成测试覆盖迁移、连接、乐观并发/事务冲突；生产安全、备份恢复和敏感信息扫描流程记录在 `baseline/docs/PRODUCTION_SECURITY.md`。
- [x] 修正严格 JSON 解码。
  - 拒绝未知字段、尾随 JSON 和任意深度重复字段；覆盖嵌套对象、batch entries 与 profile map。

### P1 · 契约、交互与自动化

- [x] 统一 API 路径和请求契约。
  - `src/lib/apiPaths.ts` 集中管理 BFF path、动态 ID 编码和 query builder；文档统一采用 `/retry`、`/replay`。
- [x] 增加前端契约、页面和截图测试。
  - Vitest 覆盖 Dashboard、Database Operations、Keys、Crypto、BatchCrypto、Audit、Lifecycle、EnvelopeConfig、Policy 的 empty/success，以及权限错误和大列表/长 ID。
  - Playwright 使用 Edge 覆盖 desktop 与 390px narrow 登录布局、水平溢出和截图基线。
- [x] 收敛前端样式与业务组件。
  - 通用 `page-header`、`page-section`、`table-scroll`、`record-card`、toolbar/filter/pagination/profile editor 类已落地。
  - Dashboard 的健康、指标、状态和可操作事项使用共享 Ops widgets；贡献约定禁止复制大段 inline layout。
- [x] 优化 BatchCrypto。
  - 支持清空、JSON/CSV 文件导入、批量粘贴、失败过滤/重试、成功结果批量复制和 UTF-8/base64/hex AAD。
- [x] 优化 EnvelopeConfig。
  - 支持 profile 表单、field mapping 行编辑、adapter/path 校验、JSON 预检、保存前 diff、乐观版本冲突重拉且保留编辑内容，以及 `aad_required`。
- [x] 完善 Audit 和 Lifecycle 大列表。
  - Audit 支持 action/result/actor/target/time range 过滤；audit/jobs/outbox 支持 cursor 分页与服务端 limit 上限。
  - outbox payload 限高，只显示并复制递归脱敏摘要。
- [x] 完成 SDK AAD canonical helper。
  - `sdk/aad` 提供 RFC 8785/JCS JSON、deterministic protobuf bytes、raw bytes 和 HTTP header allowlist canonical helper。
  - `testdata/vectors.json` 作为跨语言固定测试向量。
- [x] 对齐设计文档与实现。
  - FR 编号、Ops route、TPM/NRWK/CRK/DEK/Data 层次均已统一。
  - `ops-enhancement-design.md` 已并入《工程基线详细设计》§4.1，不再保留重复设计文档。
- [x] 增加 backend integration / E2E 测试。
  - 覆盖 APIAccess plane/scope、HMAC replay、Ops 审计 fail-closed、break-glass 负向门禁、lifecycle/outbox 幂等、Key 到期/销毁状态机、PostgreSQL 迁移与并发版本控制。

### P2 · 可维护性与开发体验

- [x] 为 `crypto/envelope`、`crypto/aad`、`resolver/keyresolver`、`tpm/provider`、`application/crypto`、`api/middleware` 补充 README。
- [x] 补充 Windows `npm.cmd`、受限沙箱 Vite/esbuild、工作区 `GOCACHE` 与缓存清理说明。
- [x] 增加前端设计系统文档。
- [x] 完善 Dashboard 信息分层。
  - 可操作事项直达 lifecycle/CRK/audit；展示最近高风险审计和 lifecycle 活动；页面明确 tenant key inventory 与全局 Ops 状态的维度差异。
  - Dashboard 只保留数据库整体状态、连接和延迟摘要；独立 Database Operations 页面通过 `ops/db/status` 可视化全局数据库聚合，不绕过平面隔离返回 Key ID、标签、记录值或密钥材料。
  - 对称 AEAD 基线将 Key purpose 收敛为 `encrypt_decrypt`；前端、服务层、加解密路径与数据库约束均拒绝不受支持的 `signing` 等用途。
  - PostgreSQL 使用事务化版本迁移账本与 advisory lock；历史 purpose 在约束前归一化，避免每次启动重复执行 DDL。
  - 前端默认提供 Daily workflow 简单模式；Policy、Envelope、Batch、Audit、Lifecycle 等控制项按需切换到 Advanced controls。
  - 启动日志输出非敏感部署体检：运行环境、存储持久性、TPM provider 和 plane 隔离级别。
  - 审计链哈希以首尾 fingerprint 紧凑展示，并支持一键复制完整 chain head/event hash；已脱敏 actor/target fingerprint 不再追加误导性的省略号。
  - Dashboard 移除与顶部状态卡重复的 Storage posture；将 Cluster 与 CRK 拆为与 Health/Database/Keys 同风格的状态卡，突出 epoch、节点、CRK 版本、状态与 AAD digest。
  - 总体设计架构图按“系统上下文 → 平面与权限 → 内部执行与可信边界”由浅入深展开；英文三层图后提供语义等价的中文三层图。
  - 新增管理面批量受控导入 Key（最多 100 条、逐条校验与结果、不回显 DEK）；批量解密与批量加密一样支持 JSON/CSV 粘贴和文件导入。
  - 提供独立 JSON/CSV 示例文件：批量 Key 导入、批量加密与批量解密各一组，并在示例 README 说明占位材料、AAD 编码与替换要求；批量解密操作区与加密对齐，支持 Clear。
  - Dashboard 全部 Health 卡均可展开查看脱敏运行态：TPM provider/PCR、Resolver CRK 缓存、数据库持久性与连接、Worker 参数与失败数、审计链校验、策略版本与受信任签名键数；不返回设备标识、DSN、密钥材料或完整审计载荷。
  - Dashboard 定义 Health 的 OK/WARN/DEGRADED 语义；TPM WARN 明确说明 `tpm2` 等兼容 provider 已初始化但低于生产原生 TPM 基线，并给出 native/tss/esapi 的升级方向。
  - Database Operations 以 Data Atlas 作为唯一的数据库库存视图（Key 总量、状态、suite、用途、数据库容量和表统计）；后端只返回全局聚合，页面不调用管理面 `/keys`。
  - 将含义错误的 `TableSizes/table_sizes` 收敛为结构化 Database Diagnostics：表项分别返回 `estimated_rows`、`table_bytes`、`index_bytes` 和统计更新时间；`pg_class.reltuples=-1` 归一为 `0` 并明确提示统计可能滞后。
  - 数据库诊断补齐连接延迟、连接池、主备角色、迁移版本、会话/锁/长事务、复制摘要、外部备份责任边界，以及孤儿 KeyVersion、销毁后材料残留和过期活跃 lease 一致性检查。
  - 数据库响应使用 `ok/warn/degraded` 和稳定原因码；不可观测指标进入 `unavailable`，不再伪装成健康零值；禁止向前端透传 PostgreSQL 原始错误、DSN 或 SQL。
  - Dashboard 的数据库重诊断按 30 秒刷新，Database Operations 按 60 秒刷新；Health 仍保持 5 秒轻量轮询。
- [x] 收敛 Envelope inspect/convert 协议边界。
  - 前端不再实现 Envelope 协议解析或重编码；只调用服务端 inspect/convert。服务端统一执行 parser/profile 选择、租户格式白名单、严格 JSON 数字边界和审计，示例文件不再硬编码策略 ID。
- [x] 完成 DESTROYED Key 归档与历史销毁任务自愈。
  - `DESTROYED` Key 支持归档 tombstone，默认 Key 库存隐藏归档项，显式 `include_archived=true` 可查看；不物理删除 Key ID、最小元数据或审计证据。
  - 启动时为缺少 `PENDING/RUNNING destroy_due` job 的历史 `DESTROY_PENDING` Key 补建销毁任务，补建时间按 `updated_at + 24h`，失败 job 仍通过 Ops retry 处理。
- [x] 增加 route-level ErrorBoundary，组件渲染异常不再导致整站空白。

## 验证记录

- `go test ./...`
- `npm.cmd test -- --run`：14 tests passed
- `npm.cmd run build`：TypeScript + Vite production build passed
- `npm.cmd run test:e2e`：desktop/narrow 2 tests passed
- TPM simulator 测试在当前 `CGO_ENABLED=0` 环境自动跳过；CI/部署验收须在启用 CGO 的 vTPM 或真实 TPM runner 上执行。
- PostgreSQL integration test 通过 `KVLT_TEST_POSTGRES_DSN` 在隔离数据库运行；本机无 Docker daemon 时自动跳过。

## 明确暂不做

- 不删除 `tpm2-tools` fallback；它仅用于 PoC、受控验证和本地联调，生产必须使用 native provider。
- 不把 `/ui/api/v1` 直接重命名为 `/api/v1`；未来公共 API 单独设计版本化契约。
- 不由服务端 canonicalize 数据面业务 AAD；服务端只消费 opaque `aad_b64` bytes，canonicalization 由调用方或 SDK 完成。
