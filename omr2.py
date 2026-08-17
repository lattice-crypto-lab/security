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

from lwe_security.constants import Q26_10

console = Console()


def section(title: str) -> None:
    console.rule(f"[bold cyan]{title}")


section("Clue")

security_model = SecurityModel.CLASSICAL
# attack_set = AttackSet.FAST_SUBSET
attack_set = AttackSet.SMART_EXACT
# attack_set = AttackSet.EXACT

n1 = 1024
q1 = 120833
lwe1_noise_stddev = 3.19
lwe1_key_distribution = ND.SparseBinary(64, n1)

result = check_lwe_security(
    n1,
    q1,
    lwe1_key_distribution,
    lwe1_noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("First BSK")
# BSK 1
N1 = 1024
Q1 = Q26_10

bsk1_stddev = 3.19
bsk1_key_distribution = ND.SparseTernary(N1 // 4, N1 // 4, N1)

result = check_lwe_security(
    N1,
    Q1,
    bsk1_key_distribution,
    bsk1_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("KSK")
n2 = 1024

ksk_noise_stddev = 3.19*512
ksk_distribution = ND.SparseBinary(64, n2)

result = check_lwe_security(
    n2,
    Q1,
    ksk_distribution,
    ksk_noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("Second BSK")
N2 = 2048
Q2 = Q50_11

# bsk2_nosie_stddev = 4.63
# bsk2_key_distribution = ND.SparseBinary(N2 // 2, N2)

bsk2_nosie_stddev = 0.849
bsk2_key_distribution = ND.SparseTernary(N2 // 8, N2 // 8, N2)

result = check_lwe_security(
    N2,
    Q2,
    bsk2_key_distribution,
    bsk2_nosie_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])
