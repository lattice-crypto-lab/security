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

section("Commit 1")
n = 512
q = 12289
noise_stddev = 3.7
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

section("Commit 2")
n = 1024
q = 18433
noise_stddev = 0.849
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

section("Commit 3")
n = 1024
q = 40961
noise_stddev = 0.849
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

section("SSLE 1")
N = 4096
Q = 1125899906826241 * 1125899906629633
noise_stddev = 0.849
key_distribution = ND.SparseTernary(N // 4, N // 4, N)

result = check_lwe_security(
    N,
    Q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("SSLE 1")
N = 4096
Q = 1125899906826241 * 1125899906629633
noise_stddev = 0.849
key_distribution = ND.SparseTernary(N // 4, N // 4, N)

result = check_lwe_security(
    N,
    Q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("SSLE 2")
N = 4096
Q = 137438822401 * 68719403009 * 68719230977
noise_stddev = 5.6
key_distribution = ND.SparseTernary(N // 4, N // 4, N)

result = check_lwe_security(
    N,
    Q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("SSLE 3")
N = 4096
Q = 137438822401 * 137438814209 * 68719403009
noise_stddev = 11.12
key_distribution = ND.SparseTernary(N // 4, N // 4, N)

result = check_lwe_security(
    N,
    Q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])

section("SSLE 4")
N = 4096
Q = 137438822401 * 137438814209 * 137438773249
noise_stddev = 22.4
key_distribution = ND.SparseTernary(N // 4, N // 4, N)

result = check_lwe_security(
    N,
    Q,
    key_distribution,
    noise_stddev,
    security_model=security_model,
    attack_set=attack_set,
)

print_security_result(result)
print_attack_results(result["run_id"])
