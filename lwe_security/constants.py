"""Shared constants for the LWE security package."""

PROFILE_ID_VERSION = 3
DEFAULT_JOBS = 1

CACHE_TIME_ZONE_NAME = "Asia/Shanghai"
RUNS_FILE_NAME = "security_runs.parquet"
ATTACK_RESULTS_FILE_NAME = "security_attack_results.parquet"

LWE_PROBLEM_TYPE = "lwe"
LWE_ESTIMATOR_NAME = "LWE.estimate"
ESTIMATOR_VERSION = "lattice-estimator-local-v1"

CLASSICAL_COST_MODEL = "BDGL16"
QUANTUM_COST_MODEL = "LaaMosPol14"
DEFAULT_SHAPE_MODEL = "GSA"
SHAPE_MODEL_TOKENS = {
    "GSA": "gsa",
}

FAST_SUBSET_DENY_LIST = (
    "arora-gb",
    "bkw",
    "bdd_hybrid",
    "bdd_mitm_hybrid",
)

EXACT_DENY_LIST = ("bkw",)

LWE_ESTIMATE_ATTACKS = (
    "arora-gb",
    "bkw",
    "usvp",
    "bdd",
    "bdd_hybrid",
    "bdd_mitm_hybrid",
    "dual",
    "dual_hybrid",
)

# Modulus constants ported from the legacy utils.py.
# Names are preserved so existing scripts can switch import sources directly.
Q27_10 = 134215681
Q27_11 = 134176769
Q27_20 = 132120577

Q29_10 = 536856577
Q29_11 = 536813569

QBabyBear = 2013265921

Q49_11 = 562949953392641
Q50_11 = 1125899906826241
Q51_11 = 2251799813640193
Q52_11 = 4503599627366401
Q53_11 = 9007199254614017
Q54_11 = 18014398509404161
Q55_11 = 36028797018820609
Q56_11 = 72057594037641217
Q57_11 = 144115188075835393
Q58_11 = 288230376151683073
Q59_11 = 576460752303419393
Q60_11 = 1152921504606830593
Q61_11 = 2305843009213616129
Q62_11 = 4611686018427322369
Q63_11 = 9223372036854497281
QGoldilocks = 0xFFFF_FFFF_0000_0001
QXX = 2**61 - 1
