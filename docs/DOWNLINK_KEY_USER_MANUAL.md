# 数传密钥用户手册

## 1. 适用范围

本文说明地面密码系统如何为星载数传加密硬件生成和上注 DEK，以及如何认证并解密硬件下传的原始密文。当前合同是 `RAW`，不解释 AOS 帧；AOS 格式冻结后只能在 RAW 数据外增加适配层，不得复制密钥生命周期。

本功能与 TC 遥控安全完全隔离：不同接口、不同密钥、不同状态和不同操作流程。下行只使用 SM4-GCM，不使用 KDF，也不使用旧 CRK/SWK 包装层。

## 2. 固定参数

| 项目 | 固定值 |
|---|---:|
| KEK 槽 | 8 个，编号 0..7 |
| KEK | 每个 16 字节 SM4 密钥；每星专用 |
| DEK | 每批 1024 个，序号 0..1023，每个 16 字节 |
| 批次代数 | 4 字节无符号大端整数，从 1 严格递增 |
| nonce | 12 字节，由发送方显式传输 |
| GCM Tag | 16 字节 |
| AAD | DEK 上注包使用头部 5 字节；RAW 下行为空 |

DEK 上注包固定为 16417 字节：

```text
KEK slot(1) | generation(4) | upload nonce(12) | encrypted DEKs(16384) | tag(16)
```

前 5 字节同时作为 GCM AAD。任何字段、密文或 Tag 被修改都会导致星载硬件拒绝该包。

RAW 下行固定为：

```text
key serial(2) | hardware nonce(12) | ciphertext(N) | tag(16)
```

`key serial` 为大端整数且必须在 0..1023。认证成功前绝不返回明文。

## 3. 首次部署

1. 复制并离线编辑 `examples/mission-security-profile.example.yaml`。
2. 替换所有示例 TC Root 和 8 个 KEK；示例值禁止用于任务环境。
3. 保证 `downlink.kek_set_hex` 恰好 256 个十六进制字符，按槽 0 到槽 7 拼接。
4. 运行一次配对部署：

```bash
go run ./cmd/ccsds-provision \
  -config ./config.production.yaml \
  -mission-profile ./mission-security-profile.yaml \
  -artifacts-dir ./private/provisioning-artifacts
```

KEK 集合会直接封装到 TPM，数据库只保存 TPM sealed object。重复执行只允许完全相同的 KEK 集合和 active slot；任何差异都会失败关闭。

数据库当前严格要求 schema version 3。系统尚未上线，因此不提供旧库迁移：若检测到旧 schema，应备份审计材料后删除旧状态库和旧软件 TPM 测试状态，再使用受控 Mission Security Profile 重新配对部署。

## 4. 生成、导出和上注

所有批次管理均为离线 CLI，不提供 Web 写接口或前端按钮。

选择下一批使用的 KEK 槽：

```bash
go run ./cmd/downlink-keyctl set-active-kek-slot \
  -config ./config.production.yaml 3
```

生成下一批并写入权限为 0600 的文件：

```bash
go run ./cmd/downlink-keyctl generate-next-dek-batch \
  -config ./config.production.yaml \
  -output ./private/upload/downlink-dek-generation.bin
```

将该文件原样交给高速上注链路。链路无需理解字段，也不得重新封装或修改。网络或硬件确认失败时，必须导出并重传同一字节序列：

```bash
go run ./cmd/downlink-keyctl export-current-dek-batch \
  -config ./config.production.yaml \
  -output ./private/upload/downlink-dek-retry.bin
```

只有系统成功认证过一次 Current 批次产生的 RAW 下行数据后，才能生成下一批。首次生成是唯一例外。该闭环免除了固定确认帧，同时阻止地面连续推进造成星地失步。

## 5. 下行解密 API

请求发送到 Data Plane：

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer <data-token>' \
  -H 'Content-Type: application/json' \
  --data @raw-downlink-request.json \
  https://ground.example/api/v1/downlink:unprotect
```

请求文件：

```json
{"package":"<RAW 下行字节的 Base64>"}
```

成功响应：

```json
{"plaintext":"<明文的 Base64>"}
```

系统先用 Current 批次中对应序号的 DEK 验证；失败后最多再用 Previous 批次验证一次。两次均失败返回 `DOWNLINK_AUTHENTICATION_FAILED`，不返回候选明文。Previous 只用于自然跨批过渡，不存在 Grace 计时器和更早批次。

## 6. 可运行示例

示例模拟数传硬件：它读取公开示例 Mission Profile 和已导出的 DEK 包，使用指定 DEK 与显式 nonce 生成可提交给 API 的 JSON。

```bash
go run ./examples/downlink-hardware-simulator \
  -mission-profile ./examples/mission-security-profile.example.yaml \
  -dek-package ./private/upload/downlink-dek-generation.bin \
  -key-serial 17 \
  -nonce-hex 000000000000000000000001 \
  -plaintext 'example payload' \
  > raw-downlink-request.json
```

模拟器仅用于联调；真实硬件必须自己保证同一 DEK 下 nonce 不重复。示例 Mission Profile、确定性 nonce 和生成的测试 DEK 都不得进入任务环境。

## 7. 运维判定与故障处理

| 现象 | 含义 | 处理 |
|---|---|---|
| `current batch has not been observed` | Current 尚未由真实下行证明 | 导出并重传同一包，不生成新批次 |
| `stored package digest mismatch` | 数据库存储被破坏或篡改 | 停止下行处理，从受控备份恢复，不绕过校验 |
| `authentication failed` | 序号、nonce、密文、Tag 或批次不匹配 | 核对硬件输出和批次，不输出明文 |
| TPM 解封失败 | TPM、PCR 策略或 sealed object 不匹配 | 停止服务，按 TPM 恢复流程处理 |
| generation 耗尽 | 32 位代数不可再递增 | 进入任务级重新配对流程，不回绕 |

数据库持久化 Current/Previous 密文包、摘要、代数、active slot 和 Current 是否被观测。进程内只缓存 Current/Previous 明文 DEK，退出时清零；KEK 不常驻缓存。

## 8. 禁止事项

- 不得通过在线 API 导入 DEK、KEK 或选择 KEK 槽。
- 不得让多个星共享 KEK，也不得把 TC Root 用作数传 KEK。
- 不得重建“相同含义但不同字节”的重传包。
- 不得接受旧 schema、缺失 Tag、非 12 字节 nonce 或序号大于 1023 的输入。
- 不得在 AOS 适配层增加第二套密钥、轮换或重放状态。
