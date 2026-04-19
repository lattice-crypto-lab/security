from estimator.estimator import *
from utils import *

lwe_n = 728
lwe_q = QBabyBear

lwe_key_type = "Binary"
lwe_stddev = 11000
print(lwe_stddev)
lwe_key_distribution = ND.SparseBinary(lwe_n // 2, lwe_n)


RLWE_N = 1024
RLWE_Q = QBabyBear

RLWE_key_type = "Ternary"
RLWE_stddev = 41.9
print(RLWE_stddev)
RLWE_key_distribution = ND.SparseTernary(RLWE_N // 4, RLWE_N // 4, RLWE_N)

check_security_with_data(lwe_n, lwe_q, lwe_key_type, lwe_key_distribution, lwe_stddev)
check_security_with_data(
    RLWE_N, RLWE_Q, RLWE_key_type, RLWE_key_distribution, RLWE_stddev
)