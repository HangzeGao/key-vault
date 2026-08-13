# 星务 TC 明文校验开发设计

- 状态：当前开发基线
- 适用范围：普通 TC `SM4-HCTR / No Tag` 接收路径
- 所有者：星务软件
- 规则来源：测控团队冻结的遥控包 ICD、字段表与正反样例

## 1. 目标与安全边界

普通 TC 在线格式固定为：

```text
Primary Header(5) | SPI(2) | IV Counter(4) | HCTR Ciphertext(N, N>=16) | FECF(2)
```

HCTR 提供宽块保密性并消除 CTR 的可控逐位翻转，但不提供密码学认证。FECF、重放窗口和明文格式校验都不能替代 MAC/Tag。本模块的目标是，在无 Tag 的既定约束下，关闭截断、拼接、未知路由、未知指令、非规范编码和越界参数等可判定输入；它不提供密码学完整性或来源认证。

明文校验位于星务软件与星载密码模块之间的 seam。星载密码模块继续只依赖一个小 interface：

```c
typedef int (*tcsec_plaintext_validator_fn)(
    void *user_context,
    const uint8_t primary_header[5],
    const uint8_t *plaintext,
    size_t plaintext_length);
```

星务提供该 interface 的唯一生产 adapter，并在 adapter 内集中实现本文全部规则。不得把同一组解析和校验散落到密码模块、指令分发器和各下位机入口。测试通过同一 interface 调用生产实现，不保留只检查魔数的发布路径。

## 2. 固定职责顺序

普通 TC 的处理顺序固定为：

```text
星载密码模块：完整帧长度、声明长度、FECF、SPI、IV replay、最大前跳
             -> SM4-HCTR 解密
星务校验模块：TC 主导头语义、Space Packet、APID 路由、指令体规范
             -> 仅返回通过或拒绝
星载密码模块：原子提交 replay/epoch
             -> 成功后才释放明文
星务业务层：  运行状态、危险性、执行联锁和指令分发
```

任一检查或状态提交失败时，输出长度必须为 0，暂存明文必须清零，replay、epoch 和 Pending 状态不得推进。

## 3. TC 传输帧主导头必选校验

回调收到的 5 字节 `primary_header` 必须满足：

| 字段 | 固定合同 |
| --- | --- |
| Frame Version Number | `00` |
| Bypass Flag | `1` |
| Control Command Flag | `0` |
| Reserved | `00` |
| Spacecraft ID | 等于本星只读配置 |
| VCID | 存在于任务冻结白名单，并与后续 APID 规则绑定 |
| Frame Length | 已由星载密码模块与实际输入长度精确核对 |
| Frame Sequence Number | 只作业务诊断，不建立第二套安全 replay 状态 |

首字节固定字段应使用掩码关闭式校验：

```c
if ((primary_header[0] & 0xFCu) != 0x20u) {
    return 0;
}
```

Spacecraft ID 与 VCID 必须按位解析后比较，不得把测试向量中的完整头字节硬编码为生产规则。

## 4. Space Packet 必选校验

当前合同规定一个普通 TC 帧数据域恰好承载一个完整、未分段的 TC Space Packet。Space Packet 主头固定为 6 字节：

```text
PVN(3) | Type(1) | SHF(1) | APID(11)
Sequence Flags(2) | Source Sequence Count(14)
Packet Data Length(16)
```

必选规则如下：

1. `plaintext_length >= 7`，即 6 字节主头后至少存在 1 字节 Packet Data Field。
2. Packet Version Number 必须为 `000`。
3. Packet Type 必须为 `1`，只接受 Telecommand。
4. 当前任务合同的 Secondary Header Flag 固定为 `0`。不得同时接受 `0/1`；若测控 ICD 最终改为存在副导头，必须先修订本文并冻结唯一副导头结构。
5. APID 必须命中任务冻结规则表；拒绝未知 APID、空闲 APID `0x7FF` 和仅为兼容保留的 APID。
6. Sequence Flags 必须为 `11`；不接受首段、续段或末段。
7. Packet Data Length 使用大端解析，且完整包长度必须精确相等：

```c
uint16_t encoded = read_be16(plaintext + 4);
size_t expected_total = 6u + (size_t)encoded + 1u;
if (expected_total != plaintext_length) {
    return 0;
}
```

8. 不接受多个 Space Packet 拼接、包尾附加字节、隐式填充、截断包或剩余未解析字节。
9. Source Sequence Count 不作为密码学认证或第二套 replay 窗口。当前 32 位 IV 是唯一安全重放状态；若业务需要检查包序，应由星务业务层按独立 ICD 实现，不得写入本回调的隐式可变状态。

## 5. APID 与遥控指令体必选校验

每个可接收 APID 必须在编译期只读规则表中绑定：

```text
允许的 VCID
允许的 Packet Data Field 精确长度或闭区间
指令版本和类型的固定值
指令码字段位置、宽度和白名单
枚举参数集合
数值参数范围
跨字段约束
保留位/保留字节的规范值
填充规则
包内校验和规则（若 ICD 定义）
```

最低规则结构建议为：

```c
typedef struct {
    uint16_t apid;
    uint64_t allowed_vcid_mask;
    uint16_t min_body_length;
    uint16_t max_body_length;
    int (*validate_body)(const uint8_t *body, size_t body_length);
} tc_packet_rule_t;
```

`validate_body` 必须完成以下检查：

- 指令体长度符合该 APID 和指令码的唯一合同；
- 指令码在明确白名单中；
- 版本、类型、子类型和枚举值均已定义；
- 数值参数在允许范围内，跨字段关系成立；
- 布尔量只接受规定编码；
- 保留位、保留字节和填充具有唯一规范值；
- ICD 定义包内校验和时必须验证，但不得将其表述为密码学认证；
- 解析结束位置必须与 body 结束位置完全一致。

禁止通用 TLV 猜测、未知字段跳过、尾随字节忽略、旧版本自动转换、宽松枚举、默认补零和失败后改用另一种格式重试。

## 6. 明确不属于本模块的检查

下列决策属于星务业务执行层，不得塞入明文格式校验 interface：

- 指令是否危险或是否需要人员审批；
- 当前姿态、电源、轨道和设备状态是否允许执行；
- 一次性动作、互斥动作、二次确认和执行速率联锁；
- 指令实际执行、排队、转发和结果反馈。

明文校验 adapter 必须是确定性的、同步的、无副作用的纯判定：不得执行或排队指令，不得修改 replay/epoch，不得保存明文副本，不得自行写 NVM。

## 7. 冻结输入与发布门禁

测控团队必须交付并冻结：

1. 本星 Spacecraft ID；
2. 允许的 VCID 集合；
3. `VCID -> APID -> 指令码` 映射；
4. 每个 APID/指令码的精确长度；
5. 指令版本、类型、枚举、参数范围与跨字段约束；
6. 保留位、填充和包内校验和规则；
7. 每条规则至少一个合法样例，以及每个字段只错一项的反例。

任务级规则表未冻结、为空、存在重叠规则或无法唯一解析时，生产构建或启动自检必须失败。测试使用的 `CA FE` 魔数规则不得编译进生产构建，也不得作为发布验收依据。

## 8. 必选测试矩阵

测试只通过 `tcsec_plaintext_validator_fn` interface 观察通过/拒绝结果，并至少覆盖：

- 每个合法 APID 和指令码的真实正例；
- TC version、bypass、control、reserved、SCID、VCID 分别单点错误；
- PVN、Type、SHF、APID、Sequence Flags 分别单点错误；
- Packet Data Length 小 1、大 1、截断、尾随和拼包；
- 未知 APID、空闲 APID、未知指令码和旧版本；
- 每个枚举、范围、跨字段、保留位和填充规则的单点反例；
- 长度 `0..TCSEC_MAX_FRAME_LENGTH` 的截断与模糊测试；
- 校验拒绝后不提交状态、不释放明文、输出缓冲区无残留；
- Current 与 Next 路径调用完全相同的生产校验实现。

HCTR 密文篡改并重算 FECF 的用例必须使用正式任务规则被拒绝。由于 HCTR 会扩散整段明文变化，该用例验证的是规则对伪随机非法明文的关闭式拒绝，仍不得宣称获得密码学完整性。

## 9. 当前剩余风险

即使本文全部规则实现，攻击者仍可能提交伪造 HCTR 密文并碰撞到结构和参数均合法的指令空间。HCTR 使攻击者不能像 CTR 那样可控地翻转目标字段，但该风险仍只能通过带 Tag 的线协议或外层认证链路消除。本文不得被引用为普通 TC 已认证、可信或具备密码学完整性的依据。
