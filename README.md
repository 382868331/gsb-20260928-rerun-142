# 软件授权验证核心（离线）

第一轮实现：使用 Go 搭建离线软件授权的**签发、导入、检查**核心。所有密钥均由
本项目临时生成（Ed25519），不连接、也不依赖任何商业授权服务。

## 结构

- `license/types.go`：授权内容与信封格式。功能项 `features`、有效期
  `not_before/not_after`、设备身份 `device_id` 为彼此独立的字段。
- `license/keyring.go`：临时签发密钥与可信公钥环；轮换时新增密钥并保留旧密钥。
- `license/revocation.go`：由签发者签名的撤销列表。
- `license/clock_anchor.go`：系统时间倒退的明确处理规则与持久化锚点。
- `license/checker.go`：统一检查入口 `Checker.Check`，后续应用复用同一接口。
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

## 命令行用法（全部离线）

```sh
go build ./cmd/license-tool

./license-tool init-issuer --issuer local-issuer      # 生成临时密钥与公钥环
./license-tool issue --license-id L1 --device DEV-X \
  --features print,scan --days 30 --out lic.json
./license-tool rotate --issuer local-issuer           # 轮换（保留旧公钥）
./license-tool check --license lic.json --device DEV-X \
  --anchor anchor.txt [--revocations rev.json] [--require-revocation]
./license-tool revoke --ids L1 --merge rev.json --out rev.json
```

## 应用集成

应用只需加载公钥环（可选撤销列表）并调用同一个检查入口：

```go
ring, _ := license.LoadKeyRing("keyring.json")
checker := &license.Checker{Ring: ring /* , Revocation: list */}
result, effectiveAt, err := checker.CheckBytes(imported, localDeviceID, lastAnchor)
```

## 测试

```sh
go test ./...
```

测试覆盖：正常签发/导入/检查、功能项与有效期及设备身份篡改、损坏授权、虚构设备
绑定、版本变更、时钟倒退、签发者轮换后旧授权有效、撤销/撤销列表损坏/资料缺失。
