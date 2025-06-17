import math
import os

import polars as pl
import datetime as dt

from estimator.estimator import *
from estimator.estimator.nd import NoiseDistribution

jobs = 16
expect_security = 128

# bits - log poly length
Q27_10 = 134215681
Q27_11 = 134176769
Q27_20 = 132120577

Q29_10 = 536856577
Q29_11 = 536813569

Q49_11 = 562949953392641
Q50_11 = 1125899906826241
Q51_11 = 2251799813640193
Q52_11 = 4503599627366401
Q53_11 = 9007199254614017
Q54_11 = 18014398509404161
Q55_11 = 36028797018820609
Q56_11 = 72057594037641217
QGoldilocks = 0xFFFF_FFFF_0000_0001

data_path = "./security_result.parquet"
# data_path = "./test.parquet"

schema = {
    "dimension": pl.UInt64,
    "modulus": pl.UInt64,
    "secret_distr": pl.String,
    "secret_stddev": pl.Float64,
    "noise_stddev": pl.Float64,
    "security_bits": pl.Float64,
    "datetime": pl.Datetime,
}

if not os.path.exists(data_path):
    df = pl.DataFrame(None, schema)
    df.write_parquet(data_path)

df = pl.read_parquet(data_path)


def write_to_data(
    dimension: int,
    modulus: int,
    secret_type: str,
    secret_distr: NoiseDistribution,
    noise_stddev,
    security,
):
    new = pl.DataFrame(
        {
            "dimension": [dimension],
            "modulus": [modulus],
            "secret_distr": [secret_type],
            "secret_stddev": [secret_distr.stddev],
            "noise_stddev": [noise_stddev],
            "security_bits": [security],
            "datetime": [dt.datetime.now()],
        },
        schema,
    )
    print(new)
    df.extend(new)
    df.write_parquet(data_path)


def print_uncheck(
    dimension: int,
    modulus: int,
    secret_type: str,
    secret_distr: NoiseDistribution,
    noise_stddev,
    security,
    pat: str,
):
    uncheck = pl.DataFrame(
        {
            "dimension": [dimension],
            "modulus": [modulus],
            "secret_distr": [secret_type],
            "secret_stddev": [secret_distr.stddev],
            "noise_stddev": [noise_stddev],
            "security_bits": [pat.format(security)],
        },
    )
    print(uncheck)


def check_security(
    dimension: int,
    modulus: int,
    secret_distr: NoiseDistribution,
    noise_stddev,
    is_quantum=False,
):
    param = LWE.Parameters(
        n=dimension, q=modulus, Xs=secret_distr, Xe=ND.DiscreteGaussian(noise_stddev)
    )
    print(param)

    try:
        result = LWE.estimate(
            param,
            red_cost_model=(RC.LaaMosPol14 if is_quantum else RC.BDGL16),
            deny_list=(
                "arora-gb",
                "bkw",
                "bdd_hybrid",
                "bdd_mitm_hybrid",
                "dual_hybrid",
                "dual_mitm_hybrid",
            ),
            jobs=jobs,
        )
    except Exception as err:
        print("err=", err)
        print("Error Occur!")
    else:
        return min([math.log(res.get("rop", 0), 2) for res in result.values()])


def check_security_with_data(
    dimension: int,
    modulus: int,
    secret_type: str,
    secret_distr: NoiseDistribution,
    noise_stddev,
    force_run_estimate: bool = False,
):
    if force_run_estimate:
        security = check_security(dimension, modulus, secret_distr, noise_stddev)
        write_to_data(
            dimension, modulus, secret_type, secret_distr, noise_stddev, security
        )
        return

    temp = df.filter(dimension=dimension, modulus=modulus, secret_distr=secret_type)
    exact = temp.filter(noise_stddev=noise_stddev)

    if exact.is_empty():
        high = temp.filter(pl.col("security_bits") >= expect_security).sort(
            "security_bits"
        )

        if (not high.is_empty()) and high.item(0, "noise_stddev") <= noise_stddev:
            print_uncheck(
                dimension,
                modulus,
                secret_type,
                secret_distr,
                noise_stddev,
                high.item(0, "security_bits"),
                ">{}",
            )
            return

        low = temp.filter(pl.col("security_bits") < expect_security).sort(
            "security_bits", descending=True
        )

        if (not low.is_empty()) and low.item(0, "noise_stddev") >= noise_stddev:
            print_uncheck(
                dimension,
                modulus,
                secret_type,
                secret_distr,
                noise_stddev,
                low.item(0, "security_bits"),
                "<{}",
            )
            return

        security = check_security(dimension, modulus, secret_distr, noise_stddev)

        write_to_data(
            dimension, modulus, secret_type, secret_distr, noise_stddev, security
        )
    else:
        print(exact)
