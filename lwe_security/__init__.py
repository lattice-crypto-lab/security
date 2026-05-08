"""Public package API for LWE security estimation helpers."""

from typing import TYPE_CHECKING, Any

from .profiles import (
    AttackSet,
    EstimationProfile,
    SecurityModel,
    get_profile,
    list_profiles,
)
from .constants import (
    Q27_10,
    Q27_11,
    Q27_20,
    Q29_10,
    Q29_11,
    Q49_11,
    Q50_11,
    Q51_11,
    Q52_11,
    Q53_11,
    Q54_11,
    Q55_11,
    Q56_11,
    Q57_11,
    Q58_11,
    Q59_11,
    Q60_11,
    Q61_11,
    Q62_11,
    Q63_11,
    QBabyBear,
    QGoldilocks,
    QXX,
)
from .types import SecurityResult

if TYPE_CHECKING:
    from .display import (
        format_attack_results,
        format_profile_comparison,
        format_security_result,
        print_attack_results,
        print_profile_comparison,
        print_security_result,
    )
    from .estimator import (
        check_lwe_security,
        check_lwe_security_exact,
        check_lwe_security_fast,
        check_lwe_security_smart_exact,
    )

_LAZY_EXPORT_MODULES = {
    "check_lwe_security": "estimator",
    "check_lwe_security_exact": "estimator",
    "check_lwe_security_fast": "estimator",
    "check_lwe_security_smart_exact": "estimator",
    "format_attack_results": "display",
    "format_profile_comparison": "display",
    "format_security_result": "display",
    "print_attack_results": "display",
    "print_profile_comparison": "display",
    "print_security_result": "display",
}

__all__ = [
    "EstimationProfile",
    "AttackSet",
    "SecurityModel",
    "SecurityResult",
    "Q27_10",
    "Q27_11",
    "Q27_20",
    "Q29_10",
    "Q29_11",
    "Q49_11",
    "Q50_11",
    "Q51_11",
    "Q52_11",
    "Q53_11",
    "Q54_11",
    "Q55_11",
    "Q56_11",
    "Q57_11",
    "Q58_11",
    "Q59_11",
    "Q60_11",
    "Q61_11",
    "Q62_11",
    "Q63_11",
    "QBabyBear",
    "QGoldilocks",
    "QXX",
    "check_lwe_security",
    "check_lwe_security_exact",
    "check_lwe_security_fast",
    "check_lwe_security_smart_exact",
    "format_attack_results",
    "format_profile_comparison",
    "format_security_result",
    "get_profile",
    "list_profiles",
    "print_attack_results",
    "print_profile_comparison",
    "print_security_result",
]


def __getattr__(name: str) -> Any:
    """Load estimator and display helpers only when they are requested."""
    module_name = _LAZY_EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    if module_name == "estimator":
        from . import estimator as module
    else:
        from . import display as module

    value = getattr(module, name)
    globals()[name] = value
    return value
