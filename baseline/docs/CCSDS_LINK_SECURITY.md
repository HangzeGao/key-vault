# CCSDS 链路安全当前契约

本系统当前只实现 CCSDS TC 上行加密和 AOS 下行解密，不提供通用协议插件或旧格式兼容层。普通 TC 固定使用 SM4-HCTR，仅 Root Prepare 使用带 16 字节 Tag 的 SM4-GCM；AOS 仍按安全关联配置使用 CMAC、CTR 或 GCM。

## TC 线格式

```text
普通 TC：Primary Header(5) | SPI(2) | IV Counter(4) | HCTR Ciphertext(N, N>=16) | FECF(2)
恢复 TC：Primary Header(5) | Recovery SPI(2) | IV Counter(4) | GCM Ciphertext(41) | Tag(16) | FECF(2)
```

地面密码系统 API 只接收 TC 数据域，返回：

```text
普通：SPI | IV | Ciphertext
恢复：SPI | IV | Ciphertext | Tag
```

测控系统拥有主导头和 FECF，不传入密钥、SPI、IV、模式、Security Epoch 或关联 ID。普通 HCTR 的 16 字节 tweak 固定为 `prefix(6) | SPI(2) | IV(4) | 0x00000000`，不在线增加字段。恢复 GCM 的 nonce 为 `prefix(6) | SPI(2) | IV(4)`，AAD 仅为线上安全头 `SPI | IV`。主导头不属于 AAD；星载模块仍独立校验帧长和 FECF。

## 密钥派生

星地各自预置相同的 Operational Root 与独立 Recovery Root。工作密钥不落库，使用 CMAC Counter KDF 即时派生：

```text
K_TC = KDF-CMAC(
  OperationalRoot,
  label="TC-TRAFFIC",
  context=SpacecraftID | Direction | Suite | SPI | SecurityEpoch | RootVersion
)

K_RECOVERY = KDF-CMAC(
  RecoveryRoot,
  label="TC-RECOVERY-GCM",
  context=SpacecraftID | RecoverySuite | RecoverySPI | RecoveryRootVersion
)
```

普通 Operational Root 固定 16 字节。SM4-CMAC KDF 派生 32 字节 HCTR 工作材料：前 16 字节为 SM4 分组密钥，后 16 字节为通用哈希密钥。Recovery Root 和派生 GCM 密钥均为 16 字节。工作材料不持久化。

## 普通 TC 自动切换

地面持久化唯一 `CURRENT` 和唯一 `NEXT` 关联。地面在计划时刻本地原子提升 `NEXT -> CURRENT`，不发送安全管理指令；之后生成的第一帧自然携带新的 SPI。

SPI 使用完整无符号 16 位范围 `0x0000..0xFFFF`。Next 的唯一规则是
`(current SPI + 1) mod 65536`，因此 `0xFFFF` 的后继是 `0x0000`。SPI 只用于选择
安全关联；Security Epoch 才是跨 SPI 回绕仍须单调递增的密钥世代标识。

星载模块只识别当前 SPI、按上述模 65536 规则相邻的 Next SPI 和独立 Recovery SPI。收到 next SPI 后：

1. 用预派生的 Next 工作材料做 SM4-HCTR 解密；
2. 调用星务实现的完整明文校验深模块；规则来源、必选字段与发布门禁以 [`TC_PLAINTEXT_VALIDATION_DESIGN.md`](TC_PLAINTEXT_VALIDATION_DESIGN.md) 为唯一开发合同；
3. 原子持久化新 epoch、SPI、root version 和 replay state；
4. 才向星务释放明文，并立即拒绝旧 SPI；
5. 派生新的 Next 工作密钥。

没有 Previous、Grace、UTC、固定确认帧或额外切换指令。HCTR 是宽块可调加密，能消除 CTR 的可控逐位翻转，但仍不提供密码学认证；明文格式校验只用于提前过滤，不能等价替代 Tag。

## 抗重放

普通 TC 使用 4 字节 IV Counter 和 64 位滑动窗口；单次最大前跳为 4096。FECF、重放、前跳和明文校验均成功后才允许持久化并释放普通指令。Recovery GCM 使用独立 replay state，不限制最大前跳，但仍拒绝重复和过旧 IV。

AOS 先做只读 replay 检查，再完成认证/解密；只有成功后才提交 replay 状态，失败认证不会消耗序号。

## 对外数据面 API

- `POST /ui/api/v1/ccsds/tc:protect`，scope `ccsds:tc:protect`；请求字段 `data` 为 Base64 TC 数据域，响应 `security_data` 为 Base64 安全域与密文。
- `POST /ui/api/v1/ccsds/aos:unprotect`，scope `ccsds:aos:unprotect`；请求字段 `frame` 为 Base64 完整 AOS 密帧，响应 `plain_frame` 为 Base64 主导头与明文数据。
- `GET /ui/api/v1/ops/ccsds/status`，Ops Plane + scope `ops:read`；只读返回 Current/Next/Recovery、TC 下一 IV 计数器及 AOS replay 高水位。接口不返回 Key ID、Root、nonce prefix 或 replay bitmap，也不提供任何切换与密钥写操作。

## 离线初始配置

安全关联只允许通过本机离线命令 `bash start.sh provision-ccsds` 初始化，不能从
HTTP 或运维前端写入。默认 profile 为：

- TC Current：`SPI=0x1001`、`SM4_HCTR`、`epoch=1`；
- TC Next：`SPI=0x1002`、`SM4_HCTR`、`epoch=2`，与 Current 共用当前 Operational Root；
- Recovery：`SPI=0x7001`、`SM4_GCM`、16 字节 Tag；
- AOS Receive：`SPI=0x2001`、`SM4_GCM`、4 字节序号、12 字节 IV、16 字节 Tag、32 帧 replay window。

命令在 TPM 边界内生成并封装协议密钥，不输出明文密钥。重复执行只接受完全一致
的现有配置；任何 SPI、算法、状态、版本或管理参数不一致都会失败关闭。

两个接口使用独立最小权限 scope，严格 JSON 解码，并按调用方租户隔离。普通测控调用者无法选择管理参数。
