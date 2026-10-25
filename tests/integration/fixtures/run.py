#!/usr/bin/env python3
"""Real B3 fixture: only owned containers/network, never host SwarmInit/prune.
Python is orchestration-only; no host dependencies are installed.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

DIND = "docker:29.6.1-dind"
PG = "postgres:18.6-alpine3.24"
GO = "golang:1.26.8-bookworm"

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("docker", timeout=30)
        self.path = str(path)
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

def api(sock, method, path, body=None):
    h = UnixHTTP(sock)
    try:
        h.request(method, "/v1.55" + path, None if body is None else json.dumps(body), {"Content-Type":"application/json"})
        r = h.getresponse()
        b = r.read()
        if r.status >= 300:
            raise RuntimeError(f"isolated Engine {method} {path}: HTTP {r.status}" + (" " + b.decode(errors="replace")[:2000] if path != "/swarm/join" else ""))
        return json.loads(b) if b else None
    finally:
        h.close()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--restic", type=Path, required=True, help="actual baseline restic 0.18.1 executable")
    p.add_argument("--minio-binary", type=Path, required=True, help="actual static CPUv1 MinIO; see build_minio.py")
    p.add_argument("--runtime", type=Path, help="NEW disposable scratch directory; secret/data contents removed at exit")
    p.add_argument("--worker", action="store_true", help="also prove real off-node rejection using second isolated engine")
    args = p.parse_args()
    work = Path(__file__).resolve().parents[3]
    root = args.runtime.resolve() if args.runtime else Path(tempfile.mkdtemp(prefix="bakabel-b3-real-", dir=os.environ["TMPDIR"]))
    if args.runtime:
        root.mkdir(mode=0o700)  # Never reuse an existing repository/data root.
    name = "bakabel-b3-" + secrets.token_hex(5)
    owned, owned_network = [], None
    cleanup = []
    outer_info = json.loads(subprocess.check_output(["docker","info","--format","{{json .}}"], text=True))
    result = {"runtime":str(root),"outer_daemon_id":outer_info["ID"],"outer_swarm_before":outer_info["Swarm"],"commands":[],"images":{}}
    def run(argv, timeout=90, check=True):
        cp = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
        # Commands contain paths, never provider/decryption credentials.
        result["commands"].append({"argv":[str(a) for a in argv],"returncode":cp.returncode,"stdout":cp.stdout,"stderr":cp.stderr})
        if check and cp.returncode:
            raise RuntimeError(f"{argv[0]} failed ({cp.returncode}): {cp.stderr[-3000:]}")
        return cp
    def docker(*argv, **kw):
        return run(["docker",*argv], **kw)
    def readinfo(name):
        return json.loads(docker("inspect",name).stdout)[0]
    def start_engine(suffix):
        n = name + suffix
        data = root / suffix.lstrip("-")
        (data/"socket").mkdir(parents=True)
        (data/"data").mkdir()
        owned.append(n)
        docker("run","-d","--name",n,"--privileged","--cpus","2","--network",owned_network,
               "--label","bakabel.integration.owner="+name,
               "--mount",f"type=bind,src={root},dst=/fixture",
               "--mount",f"type=bind,src={data/'socket'},dst=/b3-socket",
               "--mount",f"type=bind,src={data/'data'},dst=/b3-data",
               "--entrypoint","sh",DIND,"-c",
               "while [ ! -f /b3-socket/start ]; do sleep .1; done; exec dockerd --host=unix:///b3-socket/docker.sock --data-root=/b3-data --storage-driver=vfs --iptables=false --bridge=none --ip-forward=false")
        info = readinfo(n)
        run(["taskset","-pc","0,1",str(info["State"]["Pid"])])
        (data/"socket/start").touch()
        sock = data/"socket/docker.sock"
        for _ in range(100):
            try:
                info = api(sock,"GET","/info")
                break
            except (OSError,RuntimeError,http.client.HTTPException):
                time.sleep(.1)
        else:
            raise RuntimeError("isolated dockerd did not become ready")
        if info["ID"] == outer_info["ID"]:
            raise RuntimeError("refusing non-isolated daemon")
        quota = docker("exec",n,"sh","-c","read x < /sys/fs/cgroup/cpu.max; printf '%s\\n' \"$x\"").stdout.strip()
        affinity = docker("exec",n,"sh","-c", "while read -r a b; do case \"$a\" in Cpus_allowed_list:) printf '%s %s\\n' \"$a\" \"$b\";; esac; done < /proc/1/status").stdout.strip()
        result[suffix] = {"daemon_id":info["ID"],"warnings":info.get("Warnings"),"engine_pid1":readinfo(n)["State"]["Pid"],"effective_cpu_max":quota,"pid1_affinity":affinity}
        if quota != "200000 100000" or "0-1" not in affinity:
            raise RuntimeError("isolated engine effective CPU quota/affinity not verified")
        ip = next(iter(readinfo(n)["NetworkSettings"]["Networks"].values()))["IPAddress"]
        return n, sock, ip
    def load(sock, image):
        save = subprocess.Popen(["docker","save",image],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cp = subprocess.run(["docker","-H","unix://"+str(sock),"load"],stdin=save.stdout,capture_output=True,text=True,timeout=120)
        save.stdout.close()
        errors = save.communicate(timeout=120)[1]
        if cp.returncode or save.returncode:
            raise RuntimeError(f"actual image save/load failed: {cp.stderr} {errors!r}")
        result["commands"].append({"argv":["docker save",image,"| isolated docker load"],"returncode":cp.returncode,"stdout":cp.stdout})
    try:
        for d in ["bin","artifacts","secrets","destination"]:
            (root/d).mkdir()
        os.chmod(root/"artifacts",0o777)
        # Synthetic fixture credentials readable by the deliberately unprivileged
        # partial-backup worker. RO mount is verified separately. Not production ACL guidance.
        os.chmod(root/"secrets",0o755)
        user, password = "b3"+secrets.token_hex(8), secrets.token_hex(24)
        values = {"minio-user":user,"minio-password":password,"restic-password":secrets.token_hex(24),"wrong-password":secrets.token_hex(24),
                  "aws":f"[default]\naws_access_key_id = {user}\naws_secret_access_key = {password}\n",
                  "wrong-aws":"[default]\naws_access_key_id = wrongfixture\naws_secret_access_key = wrongfixturesecret\n"}
        for k,v in values.items():
            (root/"secrets"/k).write_text(v)
            os.chmod(root/"secrets"/k,0o444)
        secret_values = [user,password,values["restic-password"],values["wrong-password"]]
        shutil.copy2(args.restic.resolve(),root/"bin/restic")
        shutil.copy2(args.minio_binary.resolve(),root/"bin/minio")
        for image in [DIND,PG,GO]:
            if docker("image","inspect",image,check=False).returncode:
                docker("pull",image,timeout=180)
            inspected = json.loads(docker("image","inspect",image).stdout)[0]
            result["images"][image] = {"id":inspected["Id"],"repo_digests":inspected.get("RepoDigests")}
        build = name+"-build"
        owned.append(build)
        docker("run","--name",build,"--cpus","2","--network","none",
               "--mount",f"type=bind,src={work},dst=/src,readonly",
               "--mount",f"type=bind,src={root/'bin'},dst=/out","--workdir","/src",
               "--entrypoint","taskset",GO,"-c","0,1","sh","-c",
               "export CGO_ENABLED=0 GOAMD64=v1 GOMAXPROCS=2; go test -p 2 ./tests/integration && go test -p 2 -c -o /out/integration.test ./tests/integration",timeout=180)
        for pth in (root/"bin").iterdir():
            os.chmod(pth,0o755)
        owned_network = name+"-private"
        docker("network","create","--internal","--label","bakabel.integration.owner="+name,owned_network)
        manager, sock, ip = start_engine("-manager")
        # Scope and identity are established above. NEVER run outer swarm init.
        swarm = api(sock,"POST","/swarm/init",{"ListenAddr":"0.0.0.0:2377","AdvertiseAddr":ip,"DataPathAddr":ip,"Spec":{"Name":"default"}})
        load(sock,PG)
        worker_node = ""
        if args.worker:
            worker, wsock, wip = start_engine("-worker")
            load(wsock,PG)
            spec = api(sock,"GET","/swarm")
            api(wsock,"POST","/swarm/join",{"ListenAddr":"0.0.0.0:2377","AdvertiseAddr":wip,"DataPathAddr":wip,"RemoteAddrs":[ip+":2377"],"JoinToken":spec["JoinTokens"]["Worker"]})
            for _ in range(100):
                wi = api(wsock,"GET","/info")
                if wi["Swarm"].get("NodeID"):
                    worker_node = wi["Swarm"]["NodeID"]
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("real worker did not join")
            result["worker_node"] = worker_node
        # MinIO itself reads secret files; no shell wrapper exports their values.
        minio_spec = {"Image":PG,"Entrypoint":["/fixture/bin/integration.test"],"Cmd":["fixture-exec","/fixture/bin/minio","server","/minio-data","--address","127.0.0.1:9000"],
                      "Env":["MINIO_ROOT_USER_FILE=/credentials/minio-user","MINIO_ROOT_PASSWORD_FILE=/credentials/minio-password","MINIO_BROWSER=off","GOMAXPROCS=2"],
                      "HostConfig":{"NetworkMode":"host","Mounts":[{"Type":"bind","Source":"/fixture/bin","Target":"/fixture/bin","ReadOnly":True},{"Type":"bind","Source":"/fixture/secrets","Target":"/credentials","ReadOnly":True}],"RestartPolicy":{"Name":"no"}}}
        minio_id = api(sock,"POST","/containers/create?name=b3-minio",minio_spec)["Id"]
        api(sock,"POST",f"/containers/{minio_id}/start")
        time.sleep(2)
        result["minio"] = api(sock,"GET",f"/containers/{minio_id}/json")
        if not result["minio"]["State"]["Running"]:
            raise RuntimeError("actual MinIO failed startup")
        result["minio_version"] = docker("-H","unix://"+str(sock),"exec",minio_id,"/fixture/bin/minio","--version").stdout
        common = ["--cpus","2","--network","container:"+manager,
                  "--mount",f"type=bind,src={root/'bin'},dst=/fixture/bin,readonly",
                  "--mount",f"type=bind,src={root/'secrets'},dst=/credentials,readonly"]
        env = ["--env","RESTIC_REPOSITORY=s3:http://127.0.0.1:9000/bakabel-fixture/repository","--env","RESTIC_PASSWORD_FILE=/credentials/restic-password","--env","AWS_SHARED_CREDENTIALS_FILE=/credentials/aws","--env","AWS_DEFAULT_REGION=us-east-1","--env","GOMAXPROCS=2"]
        op = name+"-operator"
        owned.append(op)
        # EXPLICIT operator init creates both the bucket (S3 MakeBucket) and repository.
        docker("run","--name",op,*common,*env,"--entrypoint","taskset",GO,"-c","0,1","/fixture/bin/restic","--no-cache","init",timeout=40)
        runner = name+"-runner"
        owned.append(runner)
        cp = docker("run","--name",runner,*common,
                    "--mount",f"type=bind,src={root/'artifacts'},dst=/fixture/artifacts",
                    "--mount",f"type=bind,src={root/'destination'},dst=/fixture/destination",
                    "--mount",f"type=bind,src={sock},dst=/var/run/docker.sock",
                    "--env","BAKABEL_B3_OPT_IN=isolated","--env","BAKABEL_B3_OUTER_DAEMON_ID="+outer_info["ID"],
                    "--env","BAKABEL_B3_WORKER_NODE="+worker_node,
                    "--entrypoint","taskset",GO,"-c","0,1","/fixture/bin/integration.test","-test.v","-test.timeout=8m",timeout=500,check=False)
        (root/"tests.log").write_text(cp.stdout+cp.stderr)
        print(cp.stdout,end="")
        result["test_exit"] = cp.returncode
        result["inner_info_after"] = api(sock,"GET","/info")
        result["inner_services_after"] = api(sock,"GET","/services")
        result["inner_containers_after"] = api(sock,"GET","/containers/json?all=1")
        result["inner_volumes_after"] = api(sock,"GET","/volumes")
        # Only exact fixture-owned IDs on the freshly-created isolated engine.
        result["minio_logs"] = docker("-H","unix://"+str(sock),"logs",minio_id).stdout
        for c in result["inner_containers_after"]:
            api(sock,"DELETE",f"/containers/{c['Id']}?force=true&v=true")
        for v in api(sock,"GET","/volumes").get("Volumes") or []:
            api(sock,"DELETE",f"/volumes/{v['Name']}")
        result["inner_cleanup_readback"] = {"containers":api(sock,"GET","/containers/json?all=1"),"services":api(sock,"GET","/services"),"volumes":api(sock,"GET","/volumes")}
        encoded = json.dumps(result)
        for value in secret_values:
            if value in encoded:
                raise RuntimeError("synthetic credential appeared in inspect/result evidence")
        for path in (root/"artifacts").glob("*.json"):
            if any(v in path.read_text() for v in secret_values):
                raise RuntimeError("synthetic credential appeared in snapshot/checkpoint artifact")
        result["secret_scan"] = "synthetic values absent from command/inspect/result/snapshot/checkpoint evidence"
        result["artifact_inventory"] = [{"path":str(p.relative_to(root)),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in (root/"artifacts").rglob("*") if p.is_file()]
        if any(not a["path"].endswith(".json") or a["bytes"] > 65536 for a in result["artifact_inventory"]):
            raise RuntimeError("unexpected large/local data file in streaming metadata-only artifacts")
        if result["inner_cleanup_readback"]["containers"] or result["inner_cleanup_readback"]["services"] or result["inner_cleanup_readback"]["volumes"].get("Volumes"):
            raise RuntimeError("owned isolated manager resources remain after cleanup")
        if cp.returncode:
            raise RuntimeError("real integration tests failed; see tests.log")
    except Exception as exc:
        result["error"] = str(exc)
        print(str(exc),file=sys.stderr)
    finally:
        for n in reversed(owned):
            before = docker("inspect",n,check=False)
            if before.returncode == 0:
                docker("rm","-f","-v",n,timeout=40,check=False)
            absent = docker("inspect",n,check=False).returncode != 0
            cleanup.append({"container":n,"absent":absent})
        if owned_network:
            docker("network","rm",owned_network,check=False)
            cleanup.append({"network":owned_network,"absent":docker("network","inspect",owned_network,check=False).returncode!=0})
        result["cleanup"] = cleanup
        result["outer_swarm_after"] = json.loads(docker("info","--format","{{json .Swarm}}").stdout)
        result["binary_sha256"] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/"bin").glob("*") if p.is_file()}
        # Data contains namespaced root ownership. Use ONLY the exact root mount
        # in a disposable cleaner; never prune Docker or touch shared paths.
        cleaner = name+"-cleaner"
        cleanup_cp = docker("run","--rm","--name",cleaner,"--network","none","--cpus","2",
                           "--mount",f"type=bind,src={root},dst=/fixture","--entrypoint","sh",PG,"-c",
                           "rm -rf /fixture/manager /fixture/worker /fixture/secrets /fixture/destination /fixture/bin",timeout=60,check=False)
        result["private_data_removed"] = cleanup_cp.returncode == 0 and not any((root/p).exists() for p in ["manager","worker","secrets","destination","bin"])
        (root/"result.json").write_text(json.dumps(result,indent=2))
        print("Evidence:",root/"result.json")
    if result.get("error") or not result.get("private_data_removed") or not all(c["absent"] for c in cleanup):
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
