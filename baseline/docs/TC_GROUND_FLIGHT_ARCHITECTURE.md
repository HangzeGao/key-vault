# TC 地面—星载架构与流程

## 架构

```mermaid
flowchart LR
    C["测控系统\n只提交 TC 数据域 / AOS 完整密帧"]
    API["CCSDS 数据面 API\nTC protect / AOS unprotect"]
    G["地面 CCSDS 深模块\n选 Current SA、分配 IV、构造安全域"]
    P["协议无关保护核心\nTPM 解封 Root、CMAC KDF、CTR/GCM"]
    DB[("SQLite SecurityState\nCurrent/Next/Active SA、IV、Replay")]
    L["测控链路\n组主导头与 FECF"]
    F["星载 C 深模块\ntcsec_init + tcsec_receive"]
    NVM[("星载非易失存储\nRoot/epoch/SPI/replay/Pending")]
    V["测控团队提供的\n完整明文校验器"]
    O["星务指令处理"]

    C --> API --> G
    G --> DB
    G --> P
    P --> G --> L --> F
    F <--> NVM
    F --> V
    V --> F --> O
    C -->|"AOS"| API
```

星载模块不感知租户、TPM、数据库、HTTP、审批、人员权限、AOS 或地面密钥生命周期；它只感知 TC 帧结构、Current/Next/Recovery、派生上下文、重放状态、FECF、明文校验和原子持久化结果。

## 普通 TC 加解密

```mermaid
sequenceDiagram
    participant C as "测控系统"
    participant G as "地面密码系统"
    participant L as "测控链路"
    participant F as "星载密码模块"
    participant S as "星务"

    C->>G: "TC 数据域(Base64)"
    G->>G: "选择唯一 Current，原子分配 IV，派生 K_TC，CTR"
    G-->>C: "SPI | IV | Ciphertext"
    C->>L: "主导头 + 安全数据"
    L->>F: "完整帧（附 FECF）"
    F->>F: "长度/FECF/SPI/replay/最大前跳"
    F->>F: "Current 或 Next key CTR 解密"
    F->>F: "完整明文格式校验 + 原子状态提交"
    F->>S: "通过后才释放明文"
```

## 星载最小公开接口

```c
tcsec_status_t tcsec_init(tcsec_context_t *context,
                          const tcsec_config_t *config,
                          tcsec_plaintext_validator_fn validate_plaintext,
                          tcsec_state_commit_fn commit_state,
                          void *user_context);

tcsec_status_t tcsec_receive(tcsec_context_t *context,
                             const uint8_t *frame,
                             size_t frame_length,
                             uint8_t *plaintext,
                             size_t plaintext_capacity,
                             tcsec_result_t *result);

void tcsec_clear(tcsec_context_t *context);
```

工作密钥槽是 `Current / Next / Recovery`；另有 Pending Root 状态但不增加普通可接收 SPI。不存在 Previous 或 Grace 槽。
