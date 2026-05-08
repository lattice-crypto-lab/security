from __future__ import annotations

from pathlib import Path
import re
import sys
import textwrap
from typing import Any

from .cache import find_attack_results_for_run
from .types import SecurityResult


def _format_optional(value: Any, *, digits: int = 2) -> str:
    """Format an optional scalar for table output."""
    if value is None:
        return "-"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.{digits}f}"
    return str(value)


def _format_bool(value: Any) -> str:
    """Format a cache-hit boolean for display."""
    if value is True:
        return "hit"
    if value is False:
        return "miss"
    return "-"


def _format_error_note(value: Any, *, max_len: int | None = 96) -> str:
    """Return a compact one-line error note for table output."""
    if not value:
        return "-"
    text = " ".join(str(value).split())
    quick_match = re.search(r"quick_logrop≈[^\s,;]+", text)
    if quick_match and quick_match.start() > 0:
        quick = quick_match.group(0)
        text_without_quick = (
            text[: quick_match.start()] + text[quick_match.end() :]
        ).strip(" ,;")
        text = f"{quick}; {text_without_quick}"
    if max_len is None:
        return text
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 3]}..."


def _count_or_none(value: Any) -> int | None:
    """Return an integer count for display when available."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _derived_attack_counts(
    result: SecurityResult,
) -> tuple[int | None, int | None, int | None]:
    """Return attempted, finite, and incomplete attack-result counts."""
    attempted = _count_or_none(result.get("attempted_attack_count"))
    finite = _count_or_none(result.get("successful_attack_count"))
    incomplete = _count_or_none(result.get("incomplete_attack_count"))

    computed = _count_or_none(result.get("computed_attack_count"))
    reused = _count_or_none(result.get("reused_attack_count"))
    missing = _count_or_none(result.get("missing_attack_count"))
    if attempted is None and computed is not None and reused is not None:
        attempted = computed + reused
    if incomplete is None:
        incomplete = missing
    if finite is None and attempted is not None and incomplete is not None:
        finite = attempted - incomplete
    return attempted, finite, incomplete


def _security_model_title(value: Any) -> str:
    """Return a title-case security model label for display."""
    text = str(value or "").strip().lower()
    if text == "quantum":
        return "Quantum"
    if text == "classical":
        return "Classical"
    return "Security"


def _attack_source(row: dict[str, Any]) -> str:
    """Return whether an attack row was computed in the current run or reused."""
    if row.get("status") == "reused":
        return "reused"
    if row.get("source_run_id") and row.get("source_run_id") != row.get("run_id"):
        return "reused"
    return "current"


def _is_jupyter_runtime() -> bool:
    """Return whether output is likely rendered inside a Jupyter kernel."""
    if "ipykernel" in sys.modules:
        return True
    try:
        shell = get_ipython()  # type: ignore[name-defined]
    except NameError:
        return False
    return shell.__class__.__name__ == "ZMQInteractiveShell"


def _rich_print_table(
    title: str,
    headers: list[str],
    rows: list[list[Any]],
    *,
    wrap_columns: set[str] | None = None,
    expand: bool = False,
) -> bool:
    """Print a Rich table when Rich is installed, returning whether it was used."""
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return False

    is_jupyter = _is_jupyter_runtime()
    console = Console(
        force_jupyter=True,
        width=180,
    ) if is_jupyter else Console()
    wrap_min_width = 64 if is_jupyter else (
        12
        if console.width < 100
        else min(48, max(32, console.width // 4))
    )
    table = Table(title=title, box=box.ROUNDED, show_lines=False, expand=expand)
    wrap_columns = wrap_columns or set()
    for index, header in enumerate(headers):
        if header in wrap_columns:
            table.add_column(
                header,
                overflow="fold",
                ratio=2,
                min_width=wrap_min_width,
                no_wrap=False,
            )
        else:
            table.add_column(header, no_wrap=(index == 0))
    for row in rows:
        table.add_row(*(_format_optional(cell) for cell in row))
    console.print(table)
    return True


def _wrapped_cell_lines(text: str, *, width: int) -> list[str]:
    """Return display lines for one plain-text table cell."""
    if text == "-":
        return [text]
    return textwrap.wrap(
        text,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def _rows_to_table(
    headers: list[str],
    rows: list[list[Any]],
    *,
    wrap_columns: set[str] | None = None,
    wrap_width: int = 96,
) -> str:
    """Render rows as a fixed-width plain-text table."""
    wrap_columns = wrap_columns or set()
    text_rows = [[_format_optional(cell) for cell in row] for row in rows]
    line_rows = [
        [
            (
                _wrapped_cell_lines(cell, width=wrap_width)
                if headers[index] in wrap_columns
                else [cell]
            )
            for index, cell in enumerate(row)
        ]
        for row in text_rows
    ]
    widths = [
        (
            max(
                len(header),
                *(
                    len(line)
                    for row in line_rows
                    for line in row[index]
                ),
            )
            if line_rows
            else len(header)
        )
        for index, header in enumerate(headers)
    ]
    header_line = "  ".join(
        header.ljust(widths[index]) for index, header in enumerate(headers)
    )
    rule_line = "  ".join("-" * width for width in widths)
    body = []
    for row in line_rows:
        row_height = max(len(cell) for cell in row)
        for line_index in range(row_height):
            body.append(
                "  ".join(
                    (
                        row[index][line_index]
                        if line_index < len(row[index])
                        else ""
                    ).ljust(widths[index])
                    for index in range(len(headers))
                )
            )
    return "\n".join([header_line, rule_line, *body])


def _security_result_summary(result: SecurityResult) -> tuple[str, list[list[Any]]]:
    """Return the title and summary rows for one security estimate result."""
    security_model = result.get("security_model")
    security_label = _security_model_title(security_model)
    attempted_count, finite_count, incomplete_count = _derived_attack_counts(result)
    security_bits = (
        f"{result['security_bits']:.2f} bits"
        if result.get("security_bits") is not None
        else "-"
    )
    rows = [
        ("Security model", security_model),
        ("Attack set", result.get("attack_set")),
        ("Samples m", result.get("samples_m")),
        ("Status", result.get("status")),
        ("Cache", _format_bool(result.get("cache_hit"))),
        (f"{security_label} security", security_bits),
        ("Best attack", result.get("best_attack")),
        ("Attempted attacks", attempted_count),
        ("Finite results", finite_count),
        ("Incomplete results", incomplete_count),
        ("Current attempts", result.get("computed_attack_count")),
        ("Reused results", result.get("reused_attack_count")),
        ("Run id", result.get("run_id")),
    ]
    if result.get("error"):
        rows.append(("Error", result.get("error")))
    title_model = str(security_model).strip().lower() if security_model else "security"
    return (
        f"LWE {title_model} security estimate",
        [[label, value] for label, value in rows],
    )


def format_security_result(result: SecurityResult) -> str:
    """Return a human-readable summary for one security estimate result."""
    title, rows = _security_result_summary(result)
    body = _rows_to_table(
        ["Metric", "Value"],
        rows,
    )
    return f"{title}\n{body}"


def print_security_result(result: SecurityResult, *, use_rich: bool = True) -> None:
    """Print a human-readable summary for one security estimate result."""
    if use_rich:
        title, rows = _security_result_summary(result)
        if _rich_print_table(
            title,
            ["Metric", "Value"],
            rows,
        ):
            return
    print(format_security_result(result), end="\n\n")


def format_attack_results(run_id: str, cache_dir: str | Path | None = None) -> str:
    """Return a fixed-width table of cached per-attack results for one run."""
    df = find_attack_results_for_run(run_id, cache_dir)
    if df.is_empty():
        return f"Attack results\nNo attack results found for run id {run_id}."
    headers, rows = _attack_result_rows_for_display(df, truncate_error=False)
    table = _rows_to_table(headers, rows, wrap_columns={"error"})
    return f"Attack results\n{table}"


def _attack_result_rows_for_display(
    df: Any,
    *,
    truncate_error: bool = True,
) -> tuple[list[str], list[list[Any]]]:
    """Return headers and rows for one attack-result table."""
    df = df.sort("rop_log2", nulls_last=True)
    dict_rows = df.to_dicts()
    show_error = any(row.get("error") for row in dict_rows)
    headers = ["Attack", "rop(log2)", "beta", "d", "zeta", "tag", "source", "status"]
    if show_error:
        headers.append("error")
    rows = [
        (
            [
                row["attack_name"],
                row["rop_log2"],
                row["beta"],
                row["d"],
                row["zeta"],
                row["tag"],
                _attack_source(row),
                row["status"],
            ]
            + (
                [
                    _format_error_note(
                        row.get("error"),
                        max_len=96 if truncate_error else None,
                    )
                ]
                if show_error
                else []
            )
        )
        for row in dict_rows
    ]
    return headers, rows


def print_attack_results(
    run_id: str,
    cache_dir: str | Path | None = None,
    *,
    use_rich: bool = True,
) -> None:
    """Print cached per-attack results for one run."""
    if use_rich:
        df = find_attack_results_for_run(run_id, cache_dir)
        if not df.is_empty():
            headers, rows = _attack_result_rows_for_display(df, truncate_error=False)
            if _rich_print_table(
                "Attack results",
                headers,
                rows,
                wrap_columns={"error"},
                expand=True,
            ):
                return
    print(format_attack_results(run_id, cache_dir), end="\n\n")


def format_profile_comparison(results: list[SecurityResult]) -> str:
    """Return a fixed-width comparison table for multiple profile results."""
    rows = [
        [
            result.get("security_model"),
            result.get("attack_set"),
            result.get("security_bits"),
            result.get("best_attack"),
            _format_bool(result.get("cache_hit")),
            result.get("status"),
        ]
        for result in results
    ]
    table = _rows_to_table(
        [
            "Model",
            "Attack set",
            "Security bits",
            "Best attack",
            "Cache",
            "Status",
        ],
        rows,
    )
    return f"Profile comparison\n{table}"


def print_profile_comparison(
    results: list[SecurityResult],
    *,
    use_rich: bool = True,
) -> None:
    """Print a comparison table for multiple profile results."""
    if use_rich:
        rows = [
            [
                result.get("security_model"),
                result.get("attack_set"),
                result.get("security_bits"),
                result.get("best_attack"),
                _format_bool(result.get("cache_hit")),
                result.get("status"),
            ]
            for result in results
        ]
        if _rich_print_table(
            "Profile comparison",
            ["Model", "Attack set", "Security bits", "Best attack", "Cache", "Status"],
            rows,
        ):
            return
    print(format_profile_comparison(results))
