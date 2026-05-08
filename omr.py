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


section("Clue")

security_model = SecurityModel.CLASSICAL
# attack_set = AttackSet.FAST_SUBSET
attack_set = AttackSet.EXACT

n1 = 512
q1 = 2048
lwe1_noise_stddev = 0.92
lwe1_key_distribution = ND.SparseBinary(n1 // 2, n1)

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
Q1 = Q27_10

bsk1_stddev = 3.1859
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
n2 = 690

ksk_noise_stddev = 2.9 * (2**10)
ksk_distribution = ND.SparseBinary(n2 // 2, n2)

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

bsk2_nosie_stddev = 0.52
bsk2_key_distribution = ND.SparseTernary(N2 // 4, N2 // 4, N2)

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
