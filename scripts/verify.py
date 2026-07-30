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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
