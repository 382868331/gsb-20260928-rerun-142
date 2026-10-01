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
./license-tool check --license lic.json --device DEV-X \
  --anchor anchor.txt [--revocation-store rev-store.json] [--require-revocation]
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
功能项与有效期及设备身份篡改、损坏授权、虚构设备绑定、版本变更、撤销列表损坏/
资料缺失（三态）。
