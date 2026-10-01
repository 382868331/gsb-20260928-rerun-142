# 软件授权验证核心（离线）

使用 Go 搭建离线软件授权的**签发、导入、检查**核心，支持授权的**受限转授**
（多层授权链）与**离线撤销资料的单调更新**。所有密钥均由本项目临时生成
（Ed25519），不连接、也不依赖任何商业授权服务，不读取真实设备身份或真实授权
材料；测试与演练全部使用虚构设备标识和临时签发材料。

## 结构

- `license/types.go`：授权内容与信封格式。功能项 `features`、有效期
  `not_before/not_after`、设备身份 `device_id` 为彼此独立的字段。
- `license/keyring.go`：临时签发密钥与可信公钥环；轮换时新增密钥并保留旧密钥。
- `license/revocation.go`：由签发者签名的撤销列表。
- `license/clock_anchor.go`：系统时间倒退的明确处理规则与持久化锚点。
- `license/delegation.go`：受限转授。授权内嵌临时转授公钥，子授权由父授权的
  转授私钥逐层签名，构成可验证的 `LicenseChain`。
- `license/revocation_store.go`：设备本地持久化的撤销状态（序列号 + 撤销 ID
  并集），原子落盘，只接受更新的资料。
- `license/checker.go`：统一检查入口 `Checker.Check` / `Checker.CheckChain`，
  后续应用复用同一接口。
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
7. **受限转授**：授权中的 `delegation_key`（被签名覆盖）表示允许下一层转授，
   持有匹配临时私钥的一方可签发子授权。子授权**不能扩大**父授权：功能项必须是
   父级子集、设备必须完全相同、有效期窗口必须包含在父级窗口内、且不能早于父级
   签发时间。链上第 0 层必须由公钥环中的签发者密钥签名，其后每层必须由上一层
   内嵌的转授密钥签名；冒用其他密钥、伪造或事后篡改均返回
   `delegation signature verification failed`，子授权自行填写签发者 KeyID 也不
   能越权。
8. **父授权失效如何影响子授权**：链上任一层设备不符、未生效、已过期或被撤销，
   整条链即失败；撤销检查覆盖链上**全部**授权 ID（自根向叶），因此撤销父授权
   会立即阻断其下所有子授权；时钟锚点同样作用于链上每一层。
9. **撤销资料单调更新**：每份撤销列表带签发者签名的单调 `serial`。
   `RevocationStore.Apply` 只接受 `serial` 严格增大的资料；较旧或重复资料返回
   `revocation data is older than the already applied state` 且状态不变。撤销 ID
   取历次接受列表的**并集**，只增不减。状态原子写入落盘，更新中断不会破坏上一
   版状态；保存后重开仍拒绝旧资料、保留已知撤销。资料缺失
   （`not-checked-data-missing`）与检查通过（`checked`）始终分别表示。
10. **轮换后更新撤销**：轮换只新增公钥、保留旧公钥，旧授权在其有效期内仍可
    验证；新密钥签发的更高序列号撤销资料同样可以入库，不同签发者的资料拒绝。

## 命令行用法（全部离线）

```sh
go build ./cmd/license-tool

./license-tool init-issuer --issuer local-issuer      # 生成临时密钥与公钥环
./license-tool issue --license-id L1 --device DEV-X \
  --features print,scan --days 30 --out lic.json
./license-tool rotate --issuer local-issuer           # 轮换（保留旧公钥）
./license-tool check --license lic.json --device DEV-X \
  --anchor anchor.txt [--rev-store revstore.json] [--require-revocation]

# 受限转授（可多层；有效期自动裁剪到父授权窗口）
./license-tool issue ... --delegate-key-out dk1.json --out root.json
./license-tool delegate --parent root.json --delegator-key dk1.json \
  --license-id L2 --features print --days 10 --delegate-key-out dk2.json --out c1.json
./license-tool delegate --chain-in c1.json --delegator-key dk2.json \
  --license-id L3 --features print --days 5 --out chain.json
./license-tool check-chain --chain chain.json --device DEV-X \
  --anchor anchor.txt --rev-store revstore.json

# 撤销资料离线更新（序列号必须单调增大，ID 只增不减）
./license-tool revoke --serial 1 --ids L1 --out rev1.json
./license-tool rev-update --in rev1.json --store revstore.json
./license-tool revoke --serial 2 --ids L2 --merge-store revstore.json --out rev2.json
./license-tool rev-update --in rev2.json --store revstore.json
```

## 应用集成

应用只需加载公钥环（可选撤销列表）并调用同一个检查入口：

```go
ring, _ := license.LoadKeyRing("keyring.json")
store := license.NewRevocationStore("revstate.json")
_ = store.Apply(ring, signedList) // serial 必须更大，否则 ErrStaleRevocationData
checker := &license.Checker{Ring: ring, Store: store /* 或临时 Revocation: list */}
result, effectiveAt, err := checker.CheckBytes(imported, localDeviceID, lastAnchor)
chainResult, effectiveAt, err := checker.CheckChainBytes(importedChain, localDeviceID, lastAnchor)
```

## 测试

```sh
go test ./...
```

测试覆盖：正常签发/导入/检查、功能项与有效期及设备身份篡改、损坏授权、虚构设备
绑定、版本变更、时钟倒退、签发者轮换后旧授权有效、撤销/撤销列表损坏/资料缺失；
多层转授（三层链）、子授权扩大功能/设备/有效期被拒、父级无转授权与私钥不匹配、
伪造转授签名与事后篡改、子授权冒充签发者、父级过期/撤销/换设备导致整链失败、
撤销序列号回退、并集更新、轮换后更新、跨签发者拒绝、更新中断与保存重开。
