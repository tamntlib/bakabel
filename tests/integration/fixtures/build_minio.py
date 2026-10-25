#!/usr/bin/env python3
"""Fixture-only CPUv1 MinIO source build when official images are inaccessible.
No image is built/published. Source and modules remain in disposable scratch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
import urllib.request

URL = "https://codeload.github.com/minio/minio/tar.gz/refs/tags/RELEASE.2024-01-18T22-51-28Z"
SHA256 = "267c949e03f6d931f3b2da07c067f02483cb2b2604b627e1eb9b96acb0fd9192"
GO = "golang:1.26.8-bookworm"

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scratch", type=Path, required=True, help="new disposable scratch path")
    args = p.parse_args()
    root = args.scratch.resolve()
    root.mkdir(mode=0o700)
    archive = root / "minio-source.tar.gz"
    with urllib.request.urlopen(URL,timeout=60) as src, archive.open("wb") as dst:
        while block := src.read(1024*1024):
            dst.write(block)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != SHA256:
        raise RuntimeError("upstream source archive SHA-256 changed; refusing build")
    src = root / "source"
    src.mkdir()
    with tarfile.open(archive) as t:
        t.extractall(src,filter="data")
    source = next(src.iterdir())
    name = "bakabel-b3-minio-build-"+secrets.token_hex(5)
    command = ["docker","run","--name",name,"--cpus","2",
               "--mount",f"type=bind,src={source},dst=/src",
               "--mount",f"type=bind,src={root},dst=/out","--workdir","/src",
               "--entrypoint","taskset",GO,"-c","0,1","sh","-c",
               "export CGO_ENABLED=0 GOAMD64=v1 GOMAXPROCS=2; go build -p 2 -trimpath -o /out/minio ."]
    result = {"source_url":URL,"source_sha256":actual,"command":command,"warning":"upstream default DEVELOPMENT.GOGET version string retained; source provenance is the checked archive, not a release-image claim"}
    try:
        cp = subprocess.run(command,capture_output=True,text=True,timeout=600)
        (root/"build.log").write_text(cp.stdout+cp.stderr)
        result["exit_code"] = cp.returncode
        if cp.returncode:
            raise RuntimeError("actual MinIO source build failed; see build.log")
        os.chmod(root/"minio",0o755)
        result["binary_sha256"] = hashlib.sha256((root/"minio").read_bytes()).hexdigest()
        print(root/"minio")
    finally:
        subprocess.run(["docker","rm","-f","-v",name],capture_output=True,text=True,timeout=30)
        result["container_absent"] = subprocess.run(["docker","inspect",name],capture_output=True).returncode != 0
        (root/"build.json").write_text(json.dumps(result,indent=2))

if __name__ == "__main__":
    main()
