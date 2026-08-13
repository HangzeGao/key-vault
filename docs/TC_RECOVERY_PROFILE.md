# TC Recovery GCM：Root Prepare

Recovery 是与普通 SM4-HCTR TC 隔离的低频认证通道，只接受一种强类型事务：为严格相邻的 Next SPI 准备新的 Operational Root。它不承载普通遥控指令，也不直接激活新 Root。

## 帧与接口

受控管理流程向地面 CCSDS 模块提供五字节 TC 主导头模板和强类型 Root Prepare 命令。模块补齐最终帧长，分配 Recovery IV，完成 SM4-GCM 加密并生成 FECF，返回可直接发往链路的完整帧：

```text
Primary Header(5) || Recovery SPI(2) || IV_COUNTER(4)
|| GCM Ciphertext(41) || GCM Tag(16) || FECF(2)
```

GCM AAD 固定为最终的 11 字节 `Primary Header || SPI || IV_COUNTER`。因此，主导头、安全关联和 IV 的任何修改都会导致认证失败。Tag 固定为 16 字节，位于 FECF 之前。

## Root Prepare 明文

```text
format_version                 1 byte   固定为 1
transaction_id                8 bytes  非零
expected_current_root_version 4 bytes
new_root_version              4 bytes  必须更大
next_security_epoch           4 bytes  必须等于 current epoch + 1
next_spi                      2 bytes  必须等于 (current SPI + 1) mod 65536
ordinary_suite                2 bytes  固定为 SM4_HCTR (0x0013)
new_operational_root         16 bytes
```

明文总长固定为 41 字节。SPI 的合法范围是完整的 `0x0000..0xFFFF`，其中 `0xFFFF` 的相邻 Next SPI 是 `0x0000`，Security Epoch 仍必须严格加一。任何未知版本、额外尾随字节、非 SM4-HCTR 套件、Root 长度不匹配、非相邻 epoch/SPI 或当前版本不匹配均关闭式拒绝。

## 两阶段生效

```mermaid
sequenceDiagram
    participant G as "地面密码系统"
    participant M as "测控链路"
    participant F as "星载密码模块"
    G->>M: "完整 Recovery TC 帧"
    M->>F: "原样传输"
    F->>F: "长度 / FECF / replay / GCM Tag / 事务约束"
    F->>F: "原子持久化 Pending Root，并派生 Next key"
    G->>M: "首个 Next-SPI 普通 SM4-HCTR 完整帧"
    M->>F: "原样传输"
    F->>F: "解密 + 星务严格明文校验 + 原子提升"
    F-->>M: "仅此时向星务释放普通明文"
```

Root Prepare 成功只写入 Pending。真正激活发生在第一个可正确解密且通过星务完整明文校验的 Next-SPI 普通帧。该设计不需要确认帧或第二条激活指令。

## 掉电一致性

持久化适配器必须原子存储 Root Prepare 的完整事务、Recovery replay state 与 Pending Root。`tcsec_init` 恢复 Pending Root、Pending Suite、Root Version 和 Transaction ID，并重新派生 Next key，因此在 Root Prepare 与首个 Next 帧之间掉电不会遗失准备状态。

Next 提升提交必须原子完成：更新 Current SPI/Epoch/Root/Suite/replay，清除 Pending，并将原 Next key 提升为 Current。持久化失败时模块清零本次明文且不改变内存状态。

## 隔离要求

- Operational Root 和 Recovery Root 独立；Recovery Root 不派生普通流量密钥。
- Recovery 使用独立 SPI、nonce prefix、IV allocator 和 replay state。
- Recovery 明文永不复制到普通遥控输出缓冲区。
- 普通测控数据面 API 不暴露 Root Prepare；只能由受控管理流程调用。
- 链路层只传输地面 CCSDS 模块返回的完整帧，不再次组帧或改写主导头。
