from estimator.estimator import ND
from lwe_security import (
    AttackSet,
    SecurityModel,
    check_lwe_security,
    print_attack_results,
    print_security_result,
    Q50_11,
    Q27_10,
)
from rich.console import Console

console = Console()


def section(title: str) -> None:
    console.rule(f"[bold cyan]{title}")


security_model = SecurityModel.CLASSICAL
# attack_set = AttackSet.FAST_SUBSET
attack_set = AttackSet.SMART_EXACT
# attack_set = AttackSet.EXACT

section("key switch")

n = 768
# n = 1024
q = Q27_10
noise_stddev = 3.2 * (1 << 8)
# noise_stddev = 7.5
key_distribution = ND.SparseBinary(n // 2, n)

result = check_lwe_security(
    n,
    q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
    
)

print_security_result(result)
print_attack_results(result["run_id"])

section("bootstrapping")

n = 1024
q = Q27_10
noise_stddev = 4.0
key_distribution = ND.SparseTernary(n // 4, n // 4, n)

result = check_lwe_security(
    n,
    q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])
