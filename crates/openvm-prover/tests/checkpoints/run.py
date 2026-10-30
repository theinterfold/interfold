#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Opt-in real CPU proof qualification; run each phase in a separate process. See README.md."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import struct
import subprocess

HERE = Path(__file__).resolve().parent
WORKER_MANIFEST = HERE.parents[1] / "Cargo.toml"


def write(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def write_json(path, value):
    write(path, (json.dumps(value, indent=2) + "\n").encode())


def relocate(source, destination, config):
    shutil.copytree(source, destination)
    artifacts = destination / "artifacts"
    artifacts.mkdir()
    config = dict(config)
    for field in ("app_pk", "executable", "aggregation_pk", "verifier_artifact"):
        target = artifacts / field
        shutil.copyfile(config[field], target)
        config[field] = str(target)
    # Replace only the copied fixture config; checkpoint members and manifest are untouched.
    (destination / "config.json").unlink()
    write_json(destination / "config.json", config)
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "root", "compress", "verify"))
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--setup", type=Path, help="existing trusted setup, required for prepare")
    args = parser.parse_args()
    worker, out = args.worker.resolve(), args.out.resolve()

    def command(*parts, env=None):
        command = list(map(str, parts))
        print("+ " + shlex.join(command), flush=True)
        subprocess.run(command, env=env, check=True)

    def prove(stage, config, source, target):
        command(worker, stage, config, source, out / "journal.bin", target)

    if args.phase == "prepare":
        if args.setup is None:
            parser.error("prepare requires --setup")
        setup = args.setup.expanduser().resolve()
        for name in ("halo2.pk", "params", "halo2/src/v2.0-base/verifier.bytecode.json"):
            if not (setup / name).exists():
                parser.error("Missing trusted setup member: " + name)
        version = subprocess.check_output(["cargo", "openvm", "--version"], text=True)
        if "2.0.2" not in version:
            parser.error("cargo-openvm v2.0.2 is required")
        out.mkdir(mode=0o700)
        shutil.copytree(HERE / "guest", out / "guest")
        guest_args = ("--manifest-path", out / "guest/Cargo.toml",
                      "--target-dir", out / "guest-target")
        env = dict(os.environ, OPENVM_BUILD_LOCKED="1")
        command("cargo", "openvm", "build", *guest_args,
                "--output-dir", out / "guest-output", env=env)
        command("cargo", "openvm", "keygen", *guest_args, "--app-only",
                "--output-dir", out / "keys", env=env)
        command(worker, "prepare", out / "keys/app.pk",
                out / "guest-output/proof-binding-fixture.vmexe", out / "prepared")
        command(worker, "write-config", out / "config.json", out / "keys/app.pk",
                out / "guest-output/proof-binding-fixture.vmexe", out / "prepared", setup, 2**31)
        journal = bytes([7]) * 288
        digest = hashlib.sha256(journal).digest()
        write(out / "journal.bin", journal)
        write(out / "input.bin", struct.pack("<IQ", 1, len(digest)) + digest)
        command(worker, "execute", out / "config.json", out / "input.bin", out / "journal.bin")
        return

    config = json.loads((out / "config.json").read_text())
    if args.phase == "root":
        prove("prove-app", out / "config.json", out / "input.bin", out / "application")
        # The native test reads these independently of the checkpoint manifest.
        for source, name in ((config["app_pk"], "app.pk"), (config["executable"], "guest.vmexe"),
                             (out / "journal.bin", "journal.bin")):
            shutil.copyfile(source, out / "application" / name)
        write_json(out / "application/config.json", config)
        relocated = relocate(out / "application", out / "relocated-app", config)
        prove("aggregate-stark", out / "relocated-app/config.json",
              out / "relocated-app", out / "aggregate")
        write_json(out / "aggregate/config.json", relocated)
        shutil.copyfile(out / "journal.bin", out / "aggregate/journal.bin")
        prove("prove-root", out / "relocated-app/config.json", out / "aggregate", out / "root")
        write_json(out / "root/config.json", relocated)
        shutil.copyfile(out / "journal.bin", out / "root/journal.bin")
        relocate(out / "root", out / "relocated-root", relocated)
        print("Root saved. End this process, then run the compress phase.")
    elif args.phase == "compress":
        evm = out / "evm"
        evm.mkdir(mode=0o700)
        config = json.loads((out / "relocated-root/config.json").read_text())
        prove("compress-root", out / "relocated-root/config.json", out / "relocated-root", evm / "seal.bin")
        seal = (evm / "seal.bin").read_bytes()
        header = b"".join(value.to_bytes(32, "big") for value in (1, 64, 1760))
        if len(seal) != 1856 or seal[:96] != header:
            raise RuntimeError("Noncanonical seal")
        write_json(evm / "config.json", config)
        shutil.copyfile(out / "journal.bin", evm / "journal.bin")
        # Decode the existing pinned receipt encoding for the worker's independent verify command.
        proof = {"version": "v2.0", **config["app_commit"],
                 "user_public_values": "0x" + hashlib.sha256((evm / "journal.bin").read_bytes()).hexdigest(),
                 "proof_data": {"accumulator": "0x" + seal[96:480].hex(), "proof": "0x" + seal[480:].hex()}}
        write_json(evm / "proof.json", proof)
    else:
        evm = out / "evm"
        verified = out / "verification"
        verified.mkdir(mode=0o700)
        command(worker, "verify", evm / "config.json", evm / "proof.json",
                evm / "journal.bin", verified / "seal.bin")
        if (verified / "seal.bin").read_bytes() != (evm / "seal.bin").read_bytes():
            raise RuntimeError("Independent verification changed the seal")
        env = dict(os.environ, OPENVM_APP_FIXTURE=str(out / "application"),
                   OPENVM_AGGREGATE_FIXTURE=str(out / "aggregate"),
                   OPENVM_ROOT_FIXTURE=str(out / "relocated-root"), OPENVM_EVM_FIXTURE=str(evm))
        command("cargo", "test", "--locked", "--release", "--manifest-path", WORKER_MANIFEST,
                "real_", "--", "--ignored", "--test-threads=1", env=env)
        print("Genuine native proofs and EVM receipt verified, including rejection cases.")


if __name__ == "__main__":
    os.umask(0o077)
    main()
