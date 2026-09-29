# CCSDS 链路安全当前合同

## 边界

当前系统只实现 TC 遥控安全链：

- TC uplink：地面接收完整 TC 明帧，使用 Current/Next 的 SM4-HCTR 或 Recovery 的 SM4-GCM，返回完整密帧；星载 C 模块完成对称解密。

星载数传加解密硬件未确定搭载，与之相关的密钥上注、下行解密及 AOS 适配均不属于当前产物；历史实现保留在 Git 记录中。

## 隔离关系

```mermaid
flowchart LR
  M["Mission Security Profile"] --> P["Offline provisioning"]
  P --> T["TPM-sealed TC roots"]
  T --> U["TC protect API"]
```

TC Root 由 TPM 直接封装；不存在额外包装密钥层。

## 在线 API

| Plane | Endpoint | Scope |
|---|---|---|
| Data | `POST /api/v1/tc:protect` | `ccsds:tc:protect` |
| Data | `POST /api/v1/flight-status:observe` | `ccsds:flight-status:observe` |
| Ops (loopback only) | `GET /ops/v1/status` | `ops:read` |

在线接口不提供 Root、nonce prefix、计数器或轮换写操作。密钥初装由离线命令完成。

每次普通 TC protect 调用都是新的密码操作并分配新 IV Counter。链路重传可重新提交同一完整明帧，但必须保留原 TC 帧序列号；星载 TC 接收/FARM 层负责序列号去重。密码模块不实现请求幂等、密帧缓存或业务指令重复判断。

## 固定线格式

普通 TC、Recovery TC 及星载接口以 `docs/TC_GROUND_FLIGHT_ARCHITECTURE.md` 和测试向量为准。

数据库只接受 schema version 3 的 TC 表集合；含有下行状态表的数据库拒绝打开。
