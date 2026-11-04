# 星务端密码模块接口手册

适用范围：星务侧 TC 接收、Recovery Root Prepare、状态持久化和运行诊断。函数声明和结构定义以对应头文件为准。

| 功能 | 密码模块职责 | 星务/BSP 职责 |
| --- | --- | --- |
| 普通 TC | SM4-HCTR 解密、重放检查、Current/Next 切换 | 按任务规则校验明文，接收成功后执行指令 |
| Recovery TC | SM4-GCM 认证解密、解析 Root Prepare | 原子持久化待生效根和重放状态 |
| 状态恢复 | 校验星务传入的完整配置并恢复安全状态 | 选择有效持久化状态，恢复完整配置 |
| 运行诊断 | 提供不含密钥的状态和耗时统计 | 将状态字段装入任务遥测 |

## 1. TC 初始化与生命周期

接口定义：[tc_security.h](../embedded/tc_security/include/tc_security.h)。

```c
tcsec_status_t tcsec_init(tcsec_context_t *context,
                         const tcsec_config_t *config,
                         const tcsec_callbacks_t *callbacks);
tcsec_status_t tcsec_reset(tcsec_context_t *context,
                          const tcsec_config_t *config);
void tcsec_deinit(tcsec_context_t *context);
```

| 接口 | 行为 |
| --- | --- |
| `tcsec_init` | 执行密码自检，加载完整配置，绑定三个回调并派生工作密钥；返回 `TCSEC_OK` 后才开放 TC 接收 |
| `tcsec_reset` | 重新加载摘要一致的完整持久化配置，保留原回调绑定；失败保留原上下文；不写 NVM |
| `tcsec_deinit` | 清零上下文内的根密钥、工作密钥、状态和回调绑定；不擦除物理 NVM |

`tcsec_config_t` 包含 32 字节任务安全配置摘要 `profile_digest`、普通 TC 配置 `ordinary` 和 Recovery 配置 `recovery`。普通 TC 配置包含航天器标识、套件、Operational Root 及版本、当前 SPI、epoch、nonce 前缀、重放状态和待生效根信息；Recovery 配置包含套件、独立 Recovery Root 及版本、SPI、nonce 前缀和重放状态。两个根密钥均为 16 字节；没有待生效根时，各 `pending_*` 字段须为零。

上下文由星务分配，字段由模块维护。初始化复制配置中所需的密钥材料和回调结构；`user_context` 及其引用的对象必须持续有效。星务必须串行访问同一个 `tcsec_context_t`，且回调不得重入该上下文。自检失败后，`receive/reset` 均拒绝处理，返回 `TCSEC_SELF_TEST_FAILED`。

## 2. TC 接收

```c
tcsec_status_t tcsec_receive(tcsec_context_t *context,
                            const uint8_t *frame,
                            size_t frame_length,
                            uint8_t *plaintext,
                            size_t plaintext_capacity,
                            tcsec_result_t *result);
```

| 参数 | 约定 |
| --- | --- |
| `context` | 已初始化的 TC 上下文 |
| `frame`、`frame_length` | 完整 TC 密帧及实际长度，最大 1024 字节；包含主导头、安全域和 FECF |
| `plaintext`、`plaintext_capacity` | 普通 TC 明文数据域缓冲区及容量；最大数据域 1011 字节 |
| `result` | 输出 SPI、IV 计数器、处理后的安全 epoch、profile、suite 和明文长度 |

主导头为 5 字节，安全域为 6 字节（SPI 2 字节、IV 计数器 4 字节），尾部 FECF 为 2 字节。普通 TC 使用 SM4-HCTR，不带 Tag；Recovery Root Prepare 使用 SM4-GCM，Tag 为 16 字节。SPI 范围为 `0x0000～0xFFFF`，Next SPI 为 `(Current SPI + 1) mod 65536`。

| 接收结果 | 含义 | 星务处理 |
| --- | --- | --- |
| `TCSEC_OK` | Current 普通 TC 接收成功 | 按 `result.plaintext_length` 交付明文数据域 |
| `TCSEC_EPOCH_PROMOTED` | Next 普通 TC 接收成功并提升为 Current | 交付明文，记录切换事件 |
| `TCSEC_ROOT_PREPARED` | 新根准备事务已完成认证和持久化 | 记录管理事件；明文输出长度为 0 |
| `TCSEC_ROOT_ALREADY_PREPARED` | 同一根准备事务已持久化 | 记录幂等结果；明文输出长度为 0 |
| 其他返回码 | 处理失败 | 丢弃本次输出，不执行指令 |

**按上述返回码分支处理。** 三个带名称的成功事件均为非零返回值。星务只能在 `TCSEC_OK` 或 `TCSEC_EPOCH_PROMOTED` 后消费普通明文；不要依赖出错后的缓冲区内容，部分前置错误不会改写缓冲区或结果结构。调用期间，输出缓冲区不得被其他任务或 DMA 作为有效业务数据消费。

## 3. 星务必须提供的回调

通过 `tcsec_callbacks_t` 一次性传给 `tcsec_init`，并传入星务自有的 `user_context`。

```c
int validate_plaintext(void *user_context,
                       const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                       const uint8_t *plaintext,
                       size_t plaintext_length);

tcsec_commit_result_t commit_state(void *user_context,
                                   const tcsec_commit_t *commit);

uint64_t monotonic_time_us(void *user_context);
```

- **`validate_plaintext`**：检查长度、字段、指令编码和参数，返回 0 拒绝、非零通过。普通 TC 的 HCTR 不提供密码学认证，须按[正式明文校验规则](TC_PLAINTEXT_VALIDATION_DESIGN.md)实现。回调不得执行或排队指令。
- **`commit_state`**：同步、原子地持久化请求中的状态。写入及验证完成后才返回成功，不能只表示已排队。回调不得执行或排队普通指令。`commit` 及其 `root_prepare` 指针只在本次回调内有效。
- **`monotonic_time_us`**：返回单调微秒计数，仅用于接收耗时、周期超限和时钟异常统计。

| `commit->kind` | 应持久化的变更 | 模块接受的回调结果 |
| --- | --- | --- |
| `TCSEC_COMMIT_ORDINARY_REPLAY` | 普通 Current 重放状态 | `TCSEC_COMMIT_NEW` |
| `TCSEC_COMMIT_EPOCH_PROMOTION` | 新 Current SPI、epoch、对应重放状态；若存在待生效根，同时使其生效并清除 Pending 状态 | `TCSEC_COMMIT_NEW` 或 `TCSEC_COMMIT_ALREADY_APPLIED` |
| `TCSEC_COMMIT_ROOT_PREPARE` | 待生效根及事务信息、Recovery 重放状态；`commit->root_prepare` 指向根准备事务 | `TCSEC_COMMIT_NEW` 或 `TCSEC_COMMIT_ALREADY_APPLIED` |

`TCSEC_COMMIT_NEW` 表示本次新状态已持久化。`TCSEC_COMMIT_ALREADY_APPLIED` 仅在核实同一事务已经完整持久化时使用。`TCSEC_COMMIT_REJECTED` 表示拒绝，`TCSEC_COMMIT_PERSISTENCE_FAILED` 表示持久化失败。

## 4. 运行状态与诊断

```c
tcsec_status_t tcsec_get_runtime_status(const tcsec_context_t *context,
                                        tcsec_runtime_status_t *status);
```

运行状态包含自检状态、密码后端、配置摘要、Current/Next/Recovery SPI、安全 epoch、根版本、Pending 根标志，以及接收次数、最近/最大耗时、120 ms 上限超限次数和时钟异常次数。状态不含根密钥或工作密钥；自检锁定时仍会填充诊断状态，但返回 `TCSEC_SELF_TEST_FAILED`。星务负责遥测字段封装。

| TC 错误码 | 含义 |
| --- | --- |
| `TCSEC_INVALID_ARGUMENT` | 参数缺失或上下文使用方式不合法 |
| `TCSEC_INVALID_CONFIGURATION` | 配置、套件或状态提交结果不符合要求 |
| `TCSEC_FRAME_LENGTH_INVALID` | 帧长、声明长度或数据域长度非法 |
| `TCSEC_FECF_INVALID` | 帧校验失败 |
| `TCSEC_ASSOCIATION_NOT_FOUND` | SPI 不属于可接受的安全关联 |
| `TCSEC_REPLAY_REJECTED` | 帧重复、过旧或未通过重放检查 |
| `TCSEC_IV_FORWARD_JUMP_REJECTED` | 普通 TC 的 IV 前跳超过限制 |
| `TCSEC_AUTHENTICATION_FAILED` | Recovery GCM 认证失败 |
| `TCSEC_OUTPUT_TOO_SMALL` | 明文缓冲区不足 |
| `TCSEC_PLAINTEXT_REJECTED` | 星务拒绝普通 TC 明文 |
| `TCSEC_ROOT_PREPARE_REJECTED` | 根准备事务不符合当前状态 |
| `TCSEC_PERSISTENCE_FAILED` | 状态持久化失败 |
| `TCSEC_STATE_INTEGRITY_FAILED` | 上下文、状态或完整性检查失败 |
| `TCSEC_SELF_TEST_FAILED` | 自检失败或处于自检锁定状态 |

诊断只记录必要的返回码及非敏感字段，避免记录密钥、Root Prepare 明文和业务敏感明文。

## 5. 推荐接入顺序

1. 上电后，星务通过存储适配恢复完整配置。采用双槽 NVM 时，可使用附录 A 的镜像辅助库。
2. 星务提供三个回调，以完整配置调用 `tcsec_init`；返回 `TCSEC_OK` 后才开放 TC 接收。
3. 每帧调用 `tcsec_receive`。模块通过明文校验和原子持久化后，星务按返回码交付普通遥控明文。
4. 在需要发布运行遥测时调用 `tcsec_get_runtime_status`；停用时调用 `tcsec_deinit`。

运行与平台职责详见[星载密码运行闭环](FLIGHT_RUNTIME_CLOSURE.md)。

## 附录 A 可选双槽镜像辅助接口

TC 核心用 `make core` 构建。星务若采用本项目的双槽镜像格式，可另外用 `make nvm-adapter` 构建辅助库，由星务存储适配调用。静态链接时将辅助库放在核心库之前。

接口定义：[tc_security_nvm.h](../embedded/tc_security/adapters/nvm/tc_security_nvm.h)。NVM 是断电后仍能保存数据的存储器。每个槽位镜像固定为 **175 字节**，解码后的 `tcsec_nvm_image_t` 包含 `generation` 和完整 `config`。

| 接口 | 输入 | 输出及行为 |
| --- | --- | --- |
| `tcsec_nvm_encode` | 状态镜像、输出缓冲区及容量 | 生成可写入槽位的字节镜像及其长度 |
| `tcsec_nvm_decode` | 槽位字节、长度、可信 generation 下限 | 校验格式、CRC32C 及其反码、generation 和完整配置，恢复镜像 |
| `tcsec_nvm_select_latest` | 双槽字节、各自长度、可信 generation 下限 | 选出最新有效镜像及槽号 `0/1` |
| `tcsec_nvm_plan_repair` | 同上 | 返回选中镜像；恰有一槽无效时生成目标槽及下一代修复镜像 |

同一 generation 的两个有效槽必须逐字节相同；两槽均无效或同代内容冲突时拒绝恢复。调用者提供可信 generation 下限，不能因重启任意回退。写入或修复时，星务/BSP 执行物理擦写、读回并用 `tcsec_nvm_decode` 验证，成功后再推进可信下限。

镜像包含根密钥材料。星务应使用编解码接口持久化配置，不直接保存 `tcsec_context_t` 的内存布局。
