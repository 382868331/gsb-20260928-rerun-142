# 软件授权验证核心（离线）

离线软件授权的**签发、导入、受限转授、撤销资料更新与检查**核心。所有密钥
（签发密钥与转授密钥）均由本项目临时生成（Ed25519），不连接、也不依赖任何
商业授权服务；设备标识一律使用测试/虚构值，不读取真实设备身份。

## 结构

- `license/types.go`：授权内容与信封格式。功能项 `features`、有效期
  `not_before/not_after`、设备身份 `device_id` 为彼此独立的字段。
- `license/keyring.go`：临时签发密钥与可信公钥环；轮换时新增密钥并保留旧密钥。
- `license/revocation.go`：由签发者签名的撤销列表。
- `license/revocation_store.go`：按签发者持久化的最新撤销状态；严格单调，
   更新是原子替换，中断/重开不改变信任边界。
- `license/suspension.go`：带生效区间的局部停用记录（资源 + 操作）、
  取消未开始停用与提前结束生效中停用两种不同记录、使用记录复核。
- `license/suspension_store.go`：按签发者持久化的最新停用状态；严格单调、
  累积、原子替换，是离线期间保留的最近确认限制依据。
- `license/delegate.go`：受限转授（子授权）签发与范围约束校验。
- `license/clock_anchor.go`：系统时间倒退的明确处理规则与持久化锚点。
- `license/checker.go`：统一检查入口 `Checker.Check` / `Checker.CheckChain`。
- `cmd/license-tool`：离线命令行工具。

## 明确规则

1. **内容改动必失败**：签名覆盖授权全部字段；改动功能项、有效期、设备身份或
   破坏文件都会导致 `signature verification failed`。
2. **版本变更**：只接受 `version: 1`；其他版本返回 `unsupported license format
   version`，不会按猜测解析。
3. **系统时间倒退**：
   `effectiveNow = max(系统当前时间, 本设备持久化的上次观察时间)`。
   时钟回拨不会把评估时间提前，也不能延长有效期；每次检查（含过期检查）都会
   把锚点推进到有效时间，因此“先过期、再回拨”无法复活授权。检测到回拨时结果中
   `clock_rolled_back=true` 明示。
4. **签发者轮换**：轮换向公钥环加入新密钥并保留旧密钥，轮换前签发的旧授权在其
   有效期内仍可验证；环中不存在的密钥一律拒绝。
5. **撤销三态**：`checked` / `revoked` / `not-checked-data-missing`。撤销资料
   缺失时绝不声称“已检查且未撤销”；资料损坏或签名错误直接拒绝。需要严格模式时
   设置 `Checker.RequireRevocation = true`，缺失资料即失败。
6. **设备绑定**：检查时传入本机设备标识，与授权中的 `device_id` 不符即失败。
7. **受限转授**：父授权可内嵌临时转授公钥 `delegators`；子授权必须由父授权
   实际携带的转授密钥签名，并满足：功能项是父授权的子集（不能新增功能）；设备
   范围不得扩大（当前模型为单设备绑定，子授权设备必须与父授权相同）；有效期窗口
   包含在父授权窗口之内。多层转授逐级校验（`CheckChain`，根在前、叶在后）；子
   授权仍标记根签发者，撤销只接受根签发者签名的资料。
8. **父授权失效的影响**：链中任一祖先过期、未生效、被撤销或签名无效，叶子授权
   一律失效，错误同时包装 `ErrParentInvalid` 与具体原因（如 `ErrExpired`、
   `ErrRevoked`），`errors.Is` 两者都能命中。
9. **撤销资料单调更新**：每份撤销列表带严格递增的 `serial`。导入时签名必须通过
   可信公钥环验证；`serial` 小于等于已知值即判为陈旧，返回
   `ErrStaleRevocationData`，状态不变；新列表必须累积包含此前已撤销的 ID，漏掉
   一个也按回退处理；先写临时文件再原子改名，更新中断后重开仍是旧的已信任状态。
   “资料缺失”与“已检查通过”继续严格区分（三态结果不变）。
10. **局部停用（suspension）**：签发者可以签发带生效区间
    `not_before/not_after` 的停用记录，明确限制某授权的某些功能项（资源）与
    `operations`（操作）；授权本身仍然有效，其余权限照常可用。停用记录挂在
    链上任一祖先上都会向下收窄叶子授权的当前可用范围，后代授权无法借重新
    转授恢复祖先已停用的部分。评估使用回拨保护后的有效时间，时钟回拨不能
    逃离生效中的停用。
11. **取消与结束是不同记录**：`cancel-scheduled` 只能取消尚未开始的停用
    （按列表 `generated_at` 判定），把它整个抹去；`end-early` 只能作用于已
    开始的停用，把生效区间截断到 `ended_at`。两种记录混用会被拒绝
    （`ErrInvalidSuspensionRecord`），不会被静默 reinterpret。
12. **离线限制依据与复核**：接收者离线期间以本地单调存储中最近确认的停用
    列表为限制依据；取得更新（`serial` 严格递增、记录累积）后，用
    `SuspensionStore.Review` / `ReviewUsage` 重新说明哪些已有使用记录需要
    复核。只有落在限制生效区间内的使用才会被标记——后来生效的限制绝不
    改写成过去已经生效。每次验证结果（`Result.Restrictions`）都列出实际
    采用的限制事实（记录 ID、serial、区间），无签名数据时
    `SuspensionsKnown=false`，绝不把“无数据”说成“无限制”。

## 命令行用法（全部离线）

```sh
go build ./cmd/license-tool

./license-tool init-issuer --issuer local-issuer      # 生成临时密钥与公钥环
./license-tool issue --license-id L1 --device DEV-X \
  --features print,scan --days 30 --out lic.json
./license-tool rotate --issuer local-issuer           # 轮换（保留旧公钥）
./license-tool gen-delegator --key dk1.key.json        # 临时转授密钥
./license-tool issue ... --delegator-key dk1.key.json  # 父授权内嵌转授公钥
./license-tool issue-delegated --key dk1.key.json \
  --parent lic.json --issuer local-issuer --license-id L2 \
  --device DEV-X --features print --days 10 --out sub.json
./license-tool revoke --ids L1 --serial 3 --out rev3.json
./license-tool revoke-import --keyring keyring.json \
  --store rev-store.json --revocations rev3.json       # 旧 serial 拒绝、不回退
./license-tool suspend --secret issuer.key.json --records recs.json \
  --serial 1 --out susp1.json                          # 签发局部停用列表
./license-tool suspend-import --keyring keyring.json \
  --store susp-store.json --suspensions susp1.json     # 单调导入，回退拒绝
./license-tool usage-review --store susp-store.json \
  --usage usage.json                                   # 复核已有使用记录
./license-tool check --license lic.json --device DEV-X \
  --anchor anchor.txt [--revocation-store rev-store.json] [--require-revocation] \
  [--suspension-store susp-store.json]                 # 输出当前可用/已停用范围与采用事实
# 多层转授：--license 传“根,...,叶”逗号分隔的授权链
./license-tool check --license root.json,sub.json,leaf.json --device DEV-X \
  --anchor anchor.txt --revocation-store rev-store.json
```

## 应用集成

应用只需加载公钥环（可选撤销列表）并调用同一个检查入口：

```go
ring, _ := license.LoadKeyRing("keyring.json")
store, _ := license.LoadRevocationStore("rev-store.json")
_ = store.Import(ring, signedList) // 旧 serial 或丢失已撤销 ID 返回 ErrStaleRevocationData
checker := &license.Checker{Ring: ring, RevocationStore: store}
result, effectiveAt, err := checker.CheckChain(chain, localDeviceID, lastAnchor)
```

## 测试

```sh
go test ./...
```

测试覆盖：正常签发/导入/检查、多层受限转授、功能/设备/有效期扩权拒绝、伪造
转授密钥断链、父授权过期与被撤销对子授权的明确影响、签发者轮换叠加时钟回拨、
撤销资料旧 serial 与撤销 ID 丢失的回退拒绝、更新中断与保存重开后信任边界不变、
局部停用区间收窄、交叉区间与操作级限制、祖先停用向叶级传播、取消未开始与
提前结束的记录区分、使用记录复核不溯及既往、时钟回拨下停用仍然生效、
停用存储单调与保存重开后可用范围一致、
功能项与有效期及设备身份篡改、损坏授权、虚构设备绑定、版本变更、撤销列表损坏/
资料缺失（三态）。
