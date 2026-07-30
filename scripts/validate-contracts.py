"""Validate Milestone 0 schemas, fixtures, and red-first witnesses."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "policy" / "schemas" / "v1"
FIXTURES = ROOT / "tests" / "fixtures" / "contracts" / "v1"


def load(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def weaken(schema: dict[str, object], mutation: str) -> None:
    if mutation == "allow_root_additional_properties":
        schema["additionalProperties"] = True
        return
    if mutation == "remove_conditional_requirements":
        schema["allOf"] = []
        return
    if mutation == "allow_policy_grants":
        effect = schema["properties"]["rules"]["items"]["properties"]["effect"]
        effect["enum"].append("allow")
        return
    raise ValueError(f"Unknown witness mutation: {mutation}")


def errors(schema: dict[str, object], instance: object) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [error.message for error in validator.iter_errors(instance)]


def main() -> int:
    manifest = load(FIXTURES / "manifest.json")
    failures: list[str] = []

    for case in manifest["cases"]:
        schema_path = SCHEMAS / case["schema"]
        schema = load(schema_path)
        Draft202012Validator.check_schema(schema)

        valid = load(FIXTURES / "valid" / case["fixture"])
        invalid = load(FIXTURES / "invalid" / case["fixture"])

        valid_errors = errors(schema, valid)
        invalid_errors = errors(schema, invalid)
        if valid_errors:
            failures.append(f"{case['fixture']}: valid fixture rejected: {valid_errors}")
        if not invalid_errors:
            failures.append(f"{case['fixture']}: negative fixture was accepted")

        vulnerable_schema = copy.deepcopy(schema)
        weaken(vulnerable_schema, case["red_first_mutation"])
        witness_errors = errors(vulnerable_schema, invalid)
        if witness_errors:
            failures.append(
                f"{case['fixture']}: red-first witness did not expose the intended vulnerability: "
                f"{witness_errors}"
            )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print(f"Validated {len(manifest['cases'])} schemas with positive, negative, and red-first witness cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
