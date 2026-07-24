# Key Encryption Key (KEK) Upload 与 Download

Key Upload 用于将静态 Data Encryption Key (DEK) 安全地交给外部加解密设备；Key Download 用于接收设备使用 Key Encryption Key (KEK) 包装的 DEK，并重新密封到本系统的 Cryptographic Root Key (CRK) 下。核心服务不解析测控、综电或设备通信协议，协议适配方负责实际传输。

## 密钥角色

- KEK 的 `purpose` 必须为 `key_wrap`，只能通过受控导入创建，不能由普通创建接口随机生成。
- 当前交付目标是 `purpose=encrypt_decrypt`、`suite_id=SM4_GCM` 的数据密钥。
- KEK 可以使用 `AES_256_GCM` 或 `SM4_GCM`。KEK 只包装密钥，不能用于业务数据加解密。
- KEK 和数据密钥必须属于认证身份所对应的同一租户。

导入 KEK：

```http
POST /ui/api/v1/keys:import
Authorization: Bearer <management-token>
Content-Type: application/json
```

```json
{
  "key_id": "device-kek-01",
  "name": "设备预置 KEK",
  "purpose": "key_wrap",
  "policy_id": "default-v1",
  "suite_id": "SM4_GCM",
  "external_key": "<base64>"
}
```

## Key Upload

```http
POST /ui/api/v1/key-uploads
Authorization: Bearer <management-token>
Idempotency-Key: <unique-request-id>
Content-Type: application/json
```

```json
{
  "target_id": "crypto-device-01",
  "sequence": 17,
  "kek_id": "device-kek-01",
  "data_key_id": "data-key-202607",
  "data_key_version": 2
}
```

`kek_version` 和 `data_key_version` 可以省略，省略时使用各自当前版本。若要交付同一个 Key ID 下尚未激活的新版本，必须显式传入该 `PRE_ACTIVE` 版本。

响应示例：

```json
{
  "upload_id": "kup-...",
  "format_version": 1,
  "target_id": "crypto-device-01",
  "sequence": 17,
  "kek_id": "device-kek-01",
  "kek_version": 1,
  "data_key_id": "data-key-202607",
  "data_key_version": 2,
  "wrap_suite_id": "SM4_GCM",
  "nonce": "<base64>",
  "wrapped_key": "<base64>",
  "tag": "<base64>",
  "aad_b64": "<base64>",
  "status": "UPLOAD_PENDING",
  "created_at": "2026-07-23T10:00:00Z"
}
```

`target_id`、序号、KEK 与数据密钥标识和版本均包含在 `aad_b64` 中并受 GCM 认证保护。协议适配方必须原样传递设备解包所需的 `nonce`、`wrapped_key`、`tag` 和 AAD。每个租户的同一 `target_id` 不允许重复使用 `sequence`。

## 确认与激活

外部系统在收到可信的设备上注成功回执后调用：

```http
POST /ui/api/v1/key-uploads/{upload_id}/confirm
Authorization: Bearer <management-token>
```

确认接口没有请求 body，并且可以安全重试。如果上传的是 `PRE_ACTIVE` 版本，确认时将其激活，旧版本变为 `DECRYPT_ONLY`；如果上传的是已经激活的新 Key ID，确认只更新 Key Upload 状态。

可以查询交付状态：

```http
GET /ui/api/v1/key-uploads/{upload_id}
Authorization: Bearer <management-token>
```

租户始终取自认证上下文，不接受 body 或查询参数传入的 `tenant_id`。

## Key Download

设备侧先使用与系统中同 Key ID、同版本的 KEK 对数据密钥执行 GCM 加密，并按以下字段顺序生成 JSON AAD：

```json
{
  "format_version": 1,
  "download_id": "download-20260723-001",
  "target_id": "crypto-device-01",
  "sequence": 18,
  "kek_id": "device-kek-01",
  "kek_version": 1,
  "data_key_id": "downloaded-data-key",
  "data_key_version": 1,
  "data_suite_id": "SM4_GCM",
  "wrap_suite_id": "SM4_GCM"
}
```

将上述 JSON 的 UTF-8 原始字节作为 GCM AAD。下载请求为：

```http
POST /ui/api/v1/key-downloads
Authorization: Bearer <management-token>
Content-Type: application/json
```

```json
{
  "download_id": "download-20260723-001",
  "target_id": "crypto-device-01",
  "sequence": 18,
  "kek_id": "device-kek-01",
  "kek_version": 1,
  "data_key_id": "downloaded-data-key",
  "data_key_version": 1,
  "data_suite_id": "SM4_GCM",
  "name": "下载的数据密钥",
  "policy_id": "default-v1",
  "nonce": "<base64>",
  "wrapped_key": "<base64>",
  "tag": "<base64>",
  "aad_b64": "<base64>"
}
```

新 Key ID 必须使用版本 1，并提供 `name` 和 `policy_id`，导入后为 `ACTIVE`。如果 Key ID 已存在，则 `data_key_version` 必须是当前版本加一，`name` 和 `policy_id` 可省略，导入后保持 `PRE_ACTIVE`。

响应不包含明文密钥或传入的密钥密文：

```json
{
  "download_id": "download-20260723-001",
  "format_version": 1,
  "target_id": "crypto-device-01",
  "sequence": 18,
  "kek_id": "device-kek-01",
  "kek_version": 1,
  "data_key_id": "downloaded-data-key",
  "data_key_version": 1,
  "data_suite_id": "SM4_GCM",
  "operation": "CREATE_KEY",
  "status": "IMPORTED",
  "created_at": "2026-07-23T10:00:00Z",
  "imported_at": "2026-07-23T10:00:01Z"
}
```

查询状态：

```http
GET /ui/api/v1/key-downloads/{download_id}
Authorization: Bearer <management-token>
```

`download_id` 和同一目标下的 `sequence` 均不可复用。相同内容使用同一个 `download_id` 重试时会返回原结果；内容不同则拒绝。
