# TC 地面与星载密码系统架构及流程

## 1. 架构

```mermaid
flowchart LR
    subgraph G["地面密码系统"]
        GM["根密钥与 SA 管理"] --> KDF["CMAC Counter KDF"]
        KDF --> S0["普通工作密钥"]
        KDF --> S2["恢复 GCM 工作密钥"]
        SA["SPI / Suite / Prefix / IV Counter"] --> P["CCSDS TC 保护模块"]
        S0 --> P
        S2 --> P
        P --> O["普通 CTR 帧或恢复 GCM 帧"]
    end

    O --> L["测控链路"]

    subgraph F["星载密码系统"]
        L --> R["tcsec_receive"]
        T["三工作槽：当前、下一/GRACE、恢复"] --> R
        AS["SPI 绑定的严格 SA"] --> R
        R --> D{"SPI Profile"}
        D -- "Ordinary" --> C["CTR 解密、指令校验、提交重放状态"]
        D -- "Recovery" --> GCM["GCM 验证、解析唯一根恢复事务"]
        GCM --> A["平台原子提交根记录与恢复重放状态"]
    end
```

星载不感知租户、数据库、管理接口、通用密钥上传下载或动态算法注册。它只感知固定 SA、三个工作槽、帧密码处理、重放状态，以及平台提供的原子根记录适配器。

## 2. 两种帧

普通 TC 无 Tag：

```mermaid
flowchart LR
    H["主导头 5 B"] --> S["Ordinary SPI 2 B"] --> I["IV Counter 4 B"] --> C["CTR 密文 N B"] --> F["FECF 2 B"]
```

根恢复 TC 使用全长 Tag：

```mermaid
flowchart LR
    H["主导头 5 B"] --> S["Recovery SPI 2 B"] --> I["IV Counter 4 B"] --> C["GCM 密文 39/55 B"] --> T["Tag 16 B"] --> F["FECF 2 B"]
```

两者安全头都固定为 `SPI[2] || IV_COUNTER[4]`。SPI 在解密前唯一确定完整 Profile，不存在 `with_tag`、空 Tag 或自动探测。

## 3. 地面保护流程

```mermaid
flowchart TD
    A["输入 Ordinary 完整明帧或强类型 RootRecoveryCommand"] --> B["按关联 ID 读取 ACTIVE SA"]
    B --> C{"SA 方向"}
    C -- "TC_TX" --> D["验证普通帧与 CTR 套件"]
    D --> E["原子分配普通 IV"] --> F["构造 16 B CTR 初始计数块"] --> G["加密原数据域"]
    C -- "TC_RECOVERY_TX" --> H["严格编码 39/55 B 恢复事务"]
    H --> I["原子分配独立恢复 IV"] --> J["构造 12 B Nonce"] --> K["以主导头和安全头为 AAD 执行 GCM"]
    G --> M["写最终帧长并重算 FECF"]
    K --> M
```

## 4. 星载接收流程

```mermaid
flowchart TD
    A["接收完整 TC 帧"] --> B{"帧长与 FECF 合法？"}
    B -- "否" --> X["拒绝；状态不变"]
    B -- "是" --> C["解析 SPI 与 IV，只读检查重放窗口"]
    C --> D{"SPI Profile"}
    D -- "Ordinary" --> E["CTR 解密"] --> F{"指令格式/星务状态允许？"}
    F -- "否" --> X
    F -- "是" --> G["持久化重放状态"] --> H["释放普通明文"]
    D -- "Recovery" --> I["拆分固定 16 B Tag"] --> J{"GCM 认证成功？"}
    J -- "否" --> X
    J -- "是" --> K["严格解析唯一恢复事务"] --> L["原子提交根记录 + 下一恢复重放状态"]
    L --> M["返回 RECOVERY_COMMITTED/ALREADY_APPLIED；不释放明文"]
```

普通 CTR 只提供机密性；FECF 与 IV 窗口不构成密码学认证。只有专用 Recovery SPI 的 GCM 帧具备完整性和来源认证能力，且只授权根恢复事务。
