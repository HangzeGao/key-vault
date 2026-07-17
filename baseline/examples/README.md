# 批量导入示例

- `batch-key-import.*`：管理面 `POST /ui/api/v1/keys:import-batch` 的 JSON/CSV 输入示例。
- `batch-encrypt.*`：数据面批量加密页面的 JSON/CSV 输入示例。
- `batch-decrypt.*`：数据面批量解密页面的 JSON/CSV 输入示例。

示例中的 DEK 与密文均为演示占位数据，绝不可作为生产密钥或生产密文使用。批量 Key 导入固定使用 `encrypt_decrypt` 用途；`policy_id` 必须替换为 `GET /ui/api/v1/policies/signed` 返回的当前签名策略 ID；导入结果不会回显 `external_dek`。

CSV 中 AAD 建议使用 Base64，避免逗号与换行破坏列结构。批量解密示例中的 `ciphertext` 必须替换为批量加密或单条加密接口返回的 Base64 Envelope。
