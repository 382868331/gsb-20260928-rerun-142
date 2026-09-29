# 软件授权验证核心（第一轮，纯离线）

Go 实现的离线授权签发、导入与检查核心。所有密钥由本项目临时生成
（Ed25519），不连接任何商业授权服务或网络。

## 数据模型

授权令牌 `payload.signature`（两段均为 base64url）中的字段相互独立：

- 功能项：`claims[]`，每项可带语义化版本区间 `[min_version, max_version)`；
- 有效期：`not_before` / `not_after`，到期时刻（`not_after`）即失效；
- 设备身份：`device_id`，检查时必须逐字匹配；
- 轮换标识：`kid` 指定签发所用公钥；`version` 为令牌格式版本。

## 统一检查接口

应用只调用 `Checker.Check(license.Request)`，返回 `Result`：

- `status` 给出精确结果：`granted`、`expired`、`not_yet_valid`、
  `device_mismatch`、`feature_denied`、`revoked`、
  `revocation_data_missing`、`clock_rolled_back`、`invalid`；
- `revocation_checked` 仅在对“新鲜且签名有效”的撤销清单完成核验时为 true；
- 默认要求撤销清单；显式设置 `SkipRevocation` 才跳过，结果中会如实反映未检查。

## 安全规则

- **篡改必失败**：任何 payload 字节改动都会导致 Ed25519 签名验证失败。
- **时间倒退**（显式规则，容差 `ClockTolerance = 5m`）：
  - 倒退不超过容差：有效判定时间钳制为“历史观测到的最大时间”，
    不会因调表而延长授权；
  - 倒退超过容差：直接返回 `clock_rolled_back`，失败关闭；
  - 观测点持久化在状态目录的 `clock.json`。
- **签发者轮换**：`keygen` 生成新 `kid`，旧公钥保留在 `keyring.json`，
  旧授权在其自身有效期内继续验证通过；删除旧公钥则返回 `unknown_issuer`。
- **撤销**：撤销清单同样由签发者私钥签名；快照超过
  `RevocationListTTL = 30d`、缺失或签名无效时返回 `revocation_data_missing`，
  绝不冒称“已检查且无撤销”。
- **格式版本**：当前仅支持 `version=1`；签名通过但版本不受支持时返回
  `version_change` 类错误，防止把未来格式当当前格式解释。

## CLI 用法（临时密钥演示）

```bash
go build -o /tmp/licensectl ./cmd/licensectl
mkdir -p /tmp/lic-demo && cd /tmp/lic-demo
./licensectl keygen -keydir issuer -trustdir trust
./licensectl issue  -keydir issuer -device device-fictional-A \
  -features 'export@1.0:2.0,print' -days 30 -out lic.lic
./licensectl import -trustdir trust -file lic.lic
# 缺少撤销清单：revocation_data_missing，revocation_checked=false
./licensectl check  -trustdir trust -file lic.lic \
  -device device-fictional-A -feature export -app-version 1.5
# 导入一份签名撤销快照后再检查
./licensectl revoke -keydir issuer -trustdir trust -serials 'lic_xxx'
# 轮换签发者（旧授权仍在有效期内可用）
./licensectl keygen -keydir issuer -trustdir trust
```

`-now` 可传入 RFC3339 固定时间，便于测试有效期与时钟规则；
`-insecure-skip-revocation` 仅供无撤销需求的受控场景，输出会标明未检查撤销。

## 测试

```bash
go test ./...
```

测试全部使用虚构设备 `device-fictional-*`，覆盖：签发/导入/检查、篡改与损坏、
功能项与版本区间、有效期与设备绑定、密钥轮换、撤销命中/缺失/过期、
时钟倒退钳制与失败关闭、格式版本变更。
