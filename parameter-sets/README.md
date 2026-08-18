# Migrated parameter sets

本目录保存从仓库旧 Python 脚本和 Notebook 活动代码迁移出的
`lattice-security/parameter-set` v1 文件。每个文件都是可由 Web 或
`POST /v1/parameter-sets/import` 直接导入的一组方案参数。

## 映射

| 旧来源 | 新文件 | 处理说明 |
|---|---|---|
| `babybear.py` | `babybear.lattice-params.json` | LWE 与显式 coefficient-embedding RLWE |
| `goldilocks.py` | `goldilocks.lattice-params.json` | LWE 与显式 coefficient-embedding RLWE |
| `boolean.py` | `boolean.lattice-params.json` | key switch、bootstrapping |
| `omr.py` | `omr-script.lattice-params.json` | 四个活动 case |
| `omr2.py` | `omr2.lattice-params.json` | 四个活动 case |
| `ssle.py` | `ssle-script.lattice-params.json` | 重复的 SSLE 1 调用只保留一次 |
| `lwe.ipynb` | `lwe-notebook.lattice-params.json` | 仅迁移活动参数 |
| `thfhe.ipynb` | `thfhe-notebook.lattice-params.json` | 相同参数的 LWE/BSK 角色分别保留 |
| `omr.ipynb` | `omr-notebook.lattice-params.json` | 保留与脚本不同的 KSK 版本 |
| `ksbs.ipynb` | `ksbs-notebook.lattice-params.json` | 按原调用保留为 LWE |
| `nand.ipynb` | `nand-notebook.lattice-params.json` | 迁移活动 BabyBear 参数 |
| `ntru_security.ipynb` | `ntru-security-notebook.lattice-params.json` | LWE、key switching LWE、circulant NTRU |
| `ssle.ipynb` | `ssle-notebook.lattice-params.json` | 与脚本不同的 SSLE 2–4 噪声独立保留 |

所有旧 LWE 调用都未指定样本上限，因此迁移为 `unlimited`。旧方案中标注为
Binary 的密钥迁移为 `uniform_binary`。Primus 的 `sparse_ternary` 表示逐系数
独立采样，概率固定为 `P(-1)=1/4`、`P(0)=1/2`、`P(1)=1/4`，因此协议中不带
权重；只有旧参数明确偏离该概率语义时才保留为 `fixed_weight_ternary`。上游
lattice-estimator 没有对应的概率型对象，adapter 使用平衡的典型组成
`(+1,-1)≈(n/4,n/4)` 建模，但不会改变公共参数的分布类型。旧
`EXACT`/`SMART_EXACT` 是运行策略，不属于参数身份；新服务在运行时通过
“正常/快速”和慢攻击策略控制执行。

## 未生成参数文件的来源

- `prime.py` 只有 NTT-friendly 模数搜索条件，没有 secret/error 等完整问题输入；
  它应作为 sweep 约束使用，不能独立构成安全估算 case。
- `utils.py` 与 `lwe_security/` 是旧常量、缓存和调用实现，没有独立方案。
- `gaussian.ipynb` 是离散高斯采样实验，缺少维数、模数和密钥分布。
- `root.ipynb` 是有限域根实验，`static.ipynb` 是耗时统计，均不是安全估算输入。

注释掉的备选参数没有迁移。Notebook 中已有数值输出也没有转换成 computed
report，因为它们缺少可验证的 estimator commit、Sage 版本与镜像 provenance。

## 校验

`security-service/tests/migrated_parameter_sets.rs` 会遍历本目录，验证每个文件
均可由 Rust 公共类型反序列化、通过语义校验，并已使用规范十进制表示。
