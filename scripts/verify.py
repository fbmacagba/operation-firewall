"""Run the complete local verification suite without shell interpolation."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def cargo_executable() -> str:
    fallback = Path.home() / ".cargo" / "bin" / (
        "cargo.exe" if sys.platform == "win32" else "cargo"
    )
    if fallback.is_file():
        return str(fallback)
    cargo = shutil.which("cargo")
    if cargo is not None:
        return cargo
    raise FileNotFoundError("cargo is not installed or available on PATH")


def toolchain_environment() -> dict[str, str]:
    environment = os.environ.copy()
    if environment.get("RUSTUP_TOOLCHAIN"):
        return environment

    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    required = toolchain["toolchain"]["channel"]
    fallback = Path.home() / ".cargo" / "bin" / (
        "rustc.exe" if sys.platform == "win32" else "rustc"
    )
    rustc = str(fallback) if fallback.is_file() else shutil.which("rustc")
    if rustc is None:
        raise FileNotFoundError("rustc is not installed or available on PATH")

    probe_environment = environment.copy()
    probe_environment["RUSTUP_TOOLCHAIN"] = "stable"
    # Fixed argv, shell disabled, and executable constrained to Rustup/PATH discovery.
    probe = subprocess.run(  # noqa: S603
        [rustc, "--version"],
        cwd=ROOT,
        env=probe_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    installed = probe.stdout.split()[1]
    if installed == required:
        environment["RUSTUP_TOOLCHAIN"] = "stable"
    return environment


def run(command: list[str], environment: dict[str, str]) -> None:
    print(f"==> {' '.join(command)}", flush=True)
    # Callers in this module construct fixed argv arrays; no shell interpretation occurs.
    subprocess.run(command, cwd=ROOT, env=environment, check=True)  # noqa: S603


def main() -> int:
    cargo = cargo_executable()
    environment = toolchain_environment()
    run([sys.executable, "-B", "scripts/validate-contracts.py"], environment)
    run([cargo, "fmt", "--all", "--", "--check"], environment)
    run(
        [
            cargo,
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        environment,
    )
    run(
        [cargo, "test", "--workspace", "--all-targets", "--locked"],
        environment,
    )
    # `fuzz/` is excluded from the workspace so the 1.97.1 pin is not weakened
    # to enable nightly-only tooling. The cost is that every `--workspace`
    # command above is blind to it, and on 2026-08-07 that let a stale
    # assertion ship: the fuzz targets still named an operation-kind list from
    # before `git log` and `git diff` were interpreted, and nothing found out
    # until the nightly job failed on the eight-byte input `git diff`.
    #
    # Compiling the targets here does not run them -- that genuinely needs
    # nightly -- but it does catch the larger class, a target referring to an
    # API that moved underneath it. The runtime half is covered by seeding the
    # corpus, which `fuzz_regression.rs` replays on stable.
    #
    # No `--locked`: `fuzz/Cargo.lock` is not tracked, so requiring it to be
    # current would fail on a clean checkout. That also means these targets are
    # not part of the shipped artifact's dependency evidence, which is correct
    # -- they are development tooling and nothing they pull in is linked into
    # `ofw`.
    run(
        [cargo, "check", "--manifest-path", "fuzz/Cargo.toml", "--all-targets"],
        environment,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
