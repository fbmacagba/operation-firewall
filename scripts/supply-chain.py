"""Licence review and SBOM generation for the resolved dependency graph.

The Milestone 1 design requires dependency review, licence review and SBOM
generation as CI gates. This performs the two that are deterministic from the
resolved graph; advisory scanning is `cargo audit`, which runs alongside.

Failing closed matters here for the same reason it matters everywhere else in
this project: a licence this script does not recognise is not a licence this
script approves. An unknown licence is a failure, not a warning, because the
alternative is a permissive default that silently accepts the first copyleft
dependency someone adds.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Every licence expression the project accepts. Compared as exact strings
# rather than parsed: an SPDX expression parser would be another thing to get
# right, and the set of expressions actually present is small enough to
# enumerate. A new expression -- even an obviously fine one -- is a review
# event, which is the point.
ALLOWED_LICENCES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "MIT OR Apache-2.0",
        "Apache-2.0 OR MIT",
        "Apache-2.0 OR BSL-1.0",
        "Unlicense OR MIT",
        "MIT OR Unlicense",
        "(MIT OR Apache-2.0) AND Unicode-3.0",
    }
)


def cargo_metadata() -> dict:
    completed = subprocess.run(  # noqa: S603
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout)


def third_party(metadata: dict) -> list[dict]:
    """Packages that are not this workspace's own crates."""
    workspace = {
        identifier for identifier in metadata.get("workspace_members", [])
    }
    return sorted(
        (
            package
            for package in metadata["packages"]
            if package["id"] not in workspace
        ),
        key=lambda package: (package["name"], package["version"]),
    )


def review_licences(packages: list[dict]) -> int:
    problems = 0
    for package in packages:
        licence = package.get("license")
        if licence is None:
            print(
                f"FAIL {package['name']} {package['version']}: no licence field",
                file=sys.stderr,
            )
            problems += 1
        elif licence not in ALLOWED_LICENCES:
            print(
                f"FAIL {package['name']} {package['version']}: "
                f"licence {licence!r} is not in the reviewed allowlist",
                file=sys.stderr,
            )
            problems += 1
    if problems:
        print(
            f"\n{problems} package(s) failed licence review. Add the licence to "
            "ALLOWED_LICENCES in this script only after recording the review in "
            "docs/decisions/.",
            file=sys.stderr,
        )
    else:
        print(f"licence review: {len(packages)} third-party package(s) OK")
    return problems


def build_sbom(metadata: dict, packages: list[dict]) -> dict:
    """A CycloneDX 1.5 component list.

    No timestamp and no serial number: the SBOM is a function of the lockfile
    alone, so two runs over the same commit produce byte-identical output. That
    makes it diffable, which is what turns it into evidence rather than an
    artifact nobody reads.
    """
    root = metadata.get("resolve", {}).get("root")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "operation-firewall",
                "bom-ref": root or "operation-firewall",
            },
            "properties": [
                {
                    "name": "ofw:note",
                    "value": (
                        "Deterministic from Cargo.lock. No timestamp, so runs "
                        "over one commit are byte-identical."
                    ),
                }
            ],
        },
        "components": [
            {
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "purl": f"pkg:cargo/{package['name']}@{package['version']}",
                "licenses": [{"expression": package["license"]}]
                if package.get("license")
                else [],
            }
            for package in packages
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sbom",
        type=pathlib.Path,
        help="Write a CycloneDX SBOM to this path.",
    )
    arguments = parser.parse_args()

    metadata = cargo_metadata()
    packages = third_party(metadata)

    problems = review_licences(packages)

    if arguments.sbom:
        sbom = build_sbom(metadata, packages)
        arguments.sbom.parent.mkdir(parents=True, exist_ok=True)
        arguments.sbom.write_text(
            json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"sbom: {len(packages)} component(s) -> {arguments.sbom}")

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
