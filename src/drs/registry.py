from __future__ import annotations

from collections.abc import Sequence
from importlib.metadata import entry_points

from drs.config import ConfigError
from drs.models import CATEGORY_ORDER
from drs.sdk import Check


def load_checks() -> list[Check]:
    found: list[Check] = []
    for entry in entry_points(group="drs.checks"):
        loaded = entry.load()
        check: Check = loaded() if isinstance(loaded, type) else loaded
        check_id = getattr(check, "id", None)
        if not isinstance(check_id, str):
            raise RuntimeError(f"{entry.value} did not load a check")
        if check_id != entry.name:
            raise RuntimeError(f"entry point {entry.name} loads a check named {check_id}")
        found.append(check)
    return found


def select_checks(
    checks: Sequence[Check],
    include: Sequence[str],
    exclude: Sequence[str],
    timeout_ids: Sequence[str] = (),
) -> list[Check]:
    known = {check.id for check in checks}
    _unknown("include", include, known)
    _unknown("exclude", exclude, known)
    _unknown("timeouts.per_check", timeout_ids, known)
    selected = [check for check in checks if (not include or check.id in include) and check.id not in exclude]
    order = {category: index for index, category in enumerate(CATEGORY_ORDER)}
    selected.sort(key=lambda check: (order.get(check.category, len(order)), check.id))
    return selected


def _unknown(label: str, names: Sequence[str], known: set[str]) -> None:
    missing = [name for name in names if name not in known]
    if missing:
        raise ConfigError(f"unknown check id(s) in {label}: {', '.join(missing)}")
