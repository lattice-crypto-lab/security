# lwe_security

用于通过本地 `lattice-estimator` checkout 估计并缓存 LWE 参数安全级别的工具包。

这个包面向脚本/API 使用，和旧的 `utils.py` 流程保持分离。

## 公共 API

常用导入：

```python
from estimator.estimator import ND
from lwe_security import AttackSet, SecurityModel, check_lwe_security
```

运行快速 classical 估计：

```python
result = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.FAST_SUBSET,
)
```

`noise_stddev` 之后的参数都是 keyword-only，所以 profile 选择必须写成
`security_model=` 和 `attack_set=`。

稍后运行 exact classical profile：

```python
exact = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.EXACT,
)
```

如果已有兼容的 fast run，exact run 会复用已经完成的 per-attack rows，只计算缺失的攻击。

日常 final estimate 可以运行 smart-exact classical profile：

```python
smart = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.SMART_EXACT,
)
```

Smart-exact profile 始终保留标准 lattice attack surface，只智能筛选昂贵的特殊攻击
`arora-gb` 和 `bkw`。被跳过的攻击会写入 audit row，并记录 smart screen 的原因。
小规模边缘参数也可能以 calibration mode 运行昂贵攻击。成功的 calibration 结果会参与
security minimum；失败的 calibration 结果会保留用于检查，但不会让 smart-exact profile
变成 incomplete。

也可以使用 convenience wrappers：

```python
from lwe_security import (
    check_lwe_security_fast,
    check_lwe_security_exact,
    check_lwe_security_smart_exact,
)
```

## Profiles

面向用户的 profile 选择分成两个 enum 轴：

```python
SecurityModel.CLASSICAL
SecurityModel.QUANTUM

AttackSet.FAST_SUBSET
AttackSet.EXACT
AttackSet.SMART_EXACT
```

Fast subset profiles deny 的攻击族由
`lwe_security.constants.FAST_SUBSET_DENY_LIST` 配置。Exact profiles deny 的攻击族由
`lwe_security.constants.EXACT_DENY_LIST` 配置。

Smart-exact profiles 会通过 `lwe_security.smart_exact` 按参数解析 deny list。Core attacks 是：

```text
usvp
bdd
bdd_hybrid
bdd_mitm_hybrid
dual
dual_hybrid
```

Smart screen 决定是否运行：

```text
arora-gb
bkw
```

解析后的 deny list、optional calibration attacks、粗略 quick bounds 和 decision metadata
都会写入 `profile_json`，所以 profile-level cache key 可以区分不同 smart decisions 和
smart rule versions。Per-attack reuse 仍然使用 `estimate_context_hash`，因此兼容的 attack
rows 可以在 fast、exact 和 smart-exact profiles 之间复用。

缓存 row 里仍然保存派生的版本化 `profile_id`，例如 `fast_subset_classical_v3`，用于审计
和 profile-level cache identity。

Profile id 的版本由 `lwe_security.constants.PROFILE_ID_VERSION` 控制。当 profile 语义改变，
且不希望命中旧的 profile-level cache 时，应 bump 这个版本。

## Cache

默认情况下，cache 文件存放在当前工作目录：

```text
security_runs.parquet
security_attack_results.parquet
```

可以用 `cache_dir` 隔离实验：

```python
result = check_lwe_security(..., cache_dir="cache/lwe")
```

Run cache key 包含参数 descriptor、profile hash 和 estimator version。Per-attack reuse
使用 `estimate_context_hash`，它包含 estimator、cost model、shape model 和显式 `quantum`
标记，但不包含 profile deny list。

只有 successful run summary 会被当成 cache hit。Partial 或 failed runs 会留在 cache 中用于
检查，但后续调用可以重新计算同一个 profile。

使用：

```python
check_lwe_security(..., force=True, reuse_attacks=False)
```

可以重新计算请求 profile 所需的每个攻击。

使用：

```python
check_lwe_security(..., force=True, reuse_attacks=True)
```

可以创建新的 run row，同时复用兼容的 per-attack rows。

默认只复用 successful per-attack rows。如果某个 estimator attack 已知会在某组参数上失败，
并且希望后续 run 跳过同一个失败攻击的重复计算，可以使用：

```python
check_lwe_security(..., reuse_failed_attacks=True)
```

已知失败会作为 `known_error` 或 `known_no_finite_rop` 复制到新的 run。它们仍然被视为
incomplete results，所以除非所有 required attacks 都有 finite result，否则整体估计仍会是
`partial` 或 `error`。

## Display

提供纯 Python formatter：

```python
from lwe_security import print_security_result, print_attack_results

print_security_result(result)
print_attack_results(result["run_id"])
```

如果安装了 `rich`，`print_*` helpers 会自动渲染 Rich tables。传入 `use_rich=False` 可以强制
使用 plain-text 输出。

Attack table 会显示每个 row 是本次 run 计算得到，还是从兼容的历史 run 复用。

## Constants

共享常量位于 `lwe_security/constants.py`。

常见可调整项：

```python
PROFILE_ID_VERSION
DEFAULT_JOBS
FAST_SUBSET_DENY_LIST
EXACT_DENY_LIST
ESTIMATOR_VERSION
CLASSICAL_COST_MODEL
QUANTUM_COST_MODEL
DEFAULT_SHAPE_MODEL
```

Smart-exact 规则阈值位于 `lwe_security/smart_exact.py`。

从旧 `utils.py` 迁移来的 modulus constants 也可以从这里导入：

```python
from lwe_security import QBabyBear, QGoldilocks, QXX
```

`DEFAULT_JOBS` 当前为 `1`，因为 estimator 使用 multiprocessing，而 cache 层会导入 Polars。
保持 estimator 单进程可以避免当前环境中的 fork 相关不稳定性。

## Notes

- 大 modulus 会以十进制字符串形式存入 Parquet。
- `modulus_bits(q)` 返回 `ceil(log2(q))`；如果 `q` 是 2 的幂，则返回指数。
- Cache timestamp 使用 `Asia/Shanghai` 时区。
- Distribution descriptor 会区分 sparse ternary、uniform ternary、binary、Gaussian、
  centered binomial、generic uniform 和 unknown distributions。
