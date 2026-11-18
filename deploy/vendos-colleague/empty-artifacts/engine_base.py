#!/usr/bin/env python3
"""Local auth-only overlay from current container. No Docker action without --execute."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

CONTAINER = "LibreChat-API"
BACKUP_ROOT = Path("/var/backups/librechat-vendos-colleague-auth")
SOURCE_ROOT = Path("/opt/librechat")
PAYLOAD_PATHS = {
    "socialLogin.js": "/app/api/strategies/socialLogin.js",
    "checkDomainAllowed.js": "/app/api/server/middleware/checkDomainAllowed.js",
    "vendos.cjs": "/app/packages/api/dist/vendos.cjs",
    "vendos.cjs.map": "/app/packages/api/dist/vendos.cjs.map",
}
PRESERVED_PATHS = {
    "VendosBriefing.js": "/app/api/server/services/VendosBriefing.js",
    "request.js": "/app/api/server/controllers/agents/request.js",
    "MCP.js": "/app/api/server/services/MCP.js",
    "PluginService.js": "/app/api/server/services/PluginService.js",
    "api-package.json": "/app/packages/api/package.json",
}
PATHS = {**PAYLOAD_PATHS, **PRESERVED_PATHS}
EXPECTED_VENDOS_BASELINE = 'f5b240afe88c7eaf0e02d1ef2fb0d592ebf73fe05f1e25c42de445275b43cf28'
ENV_PATCH = {
    'VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST': '14322c63c114759593f4985f41d3ad3b9580dfd532dfcf125695ccd4b5eff11c',
}
# Engine recreation copies every label. No generated/custom label exception needed.
GENERATED_LABELS = set()
ZERO_GATE_FIELDS = (
    "running_jobs", "requires_action_jobs", "owner_paused_jobs",
    "pending_execution_approvals", "pending_draft_decisions", "unexpired_bridge_leases",
)
CONTROLLED_GATE_FIELDS = (
    "pending_execution_approvals", "pending_draft_decisions",
    "unexpired_bridge_leases", "unacknowledged_deliveries",
)


class Refusal(Exception):
    def __init__(self, code: str):
        self.code = code


def demand(condition: bool, code: str) -> None:
    if not condition:
        raise Refusal(code)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def freeze_compose(value: object) -> object:
    """Escape interpolation in a resolved Compose model before saving it."""
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, list):
        return [freeze_compose(item) for item in value]
    if isinstance(value, dict):
        return {key: freeze_compose(item) for key, item in value.items()}
    return value


def env_map(items: list[str]) -> dict[str, str]:
    result = {}
    for item in items:
        demand(isinstance(item, str) and "=" in item, "INVALID_ENVIRONMENT")
        key, value = item.split("=", 1)
        demand(key not in result, "DUPLICATE_ENVIRONMENT")
        result[key] = value
    return result


def mount_collision(mounts: list[dict], paths: list[str]) -> bool:
    for mount in mounts:
        destination = mount["Destination"].rstrip("/") or "/"
        for path in paths:
            if destination == "/" or path == destination or path.startswith(destination + "/"):
                return True
    return False


def canonical_inspect(record: dict) -> dict:
    host_config = dict(record['HostConfig'])
    # Moby defaults an omitted OomKillDisable pointer to false on create.
    if host_config.get('OomKillDisable') is None:
        host_config['OomKillDisable'] = False
    config = dict(record["Config"])
    config.pop("Image", None)
    config["Env"] = env_map(config.get("Env") or [])
    config["Labels"] = {
        k: v for k, v in (config.get("Labels") or {}).items() if k not in GENERATED_LABELS
    }
    # Docker derives only an unspecified hostname from the container ID.
    if config.get("Hostname") == record["Id"][:12]:
        config["Hostname"] = "<docker-default>"
    networks = {}
    for name, network in record["NetworkSettings"]["Networks"].items():
        networks[name] = {
            "Aliases": sorted(
                alias for alias in (network.get("Aliases") or [])
                if alias not in (record["Id"], record["Id"][:12])
            ),
            "Links": sorted(network.get("Links") or []),
            "IPAMConfig": network.get("IPAMConfig"),
            "DriverOpts": network.get("DriverOpts"),
            "GwPriority": network.get("GwPriority", 0),
        }
    # Ignore only assigned endpoints/IPs and process state. All resource limits,
    # namespace settings, capabilities and log settings remain in HostConfig.
    return {
        "Name": record["Name"],
        "Config": config,
        "HostConfig": host_config,
        "Mounts": sorted(record["Mounts"], key=lambda m: m["Destination"]),
        "Networks": networks,
    }


def assert_parity(before: dict, after: dict, expected_image: str, expected_name: str | None = None,
                  env_patch: dict | None = None) -> None:
    demand(after["Image"] == expected_image, "WRONG_IMAGE")
    expected, actual = canonical_inspect(before), canonical_inspect(after)
    if env_patch is not None:
        validate_env_patch(before, env_patch)
        expected['Config']['Env'].update(env_patch)
    if expected_name is not None:
        expected["Name"] = "/" + expected_name
    if (before["Config"].get("Hostname") == before["Id"][:12]
            and after["Config"].get("Hostname") == before["Config"]["Hostname"]):
        actual["Config"]["Hostname"] = "<docker-default>"
    demand(expected == actual, "RUNTIME_CONFIGURATION_DRIFT")
    if after["State"].get("Running"):
        demand(all(network.get("NetworkID") == after["NetworkSettings"]["Networks"][name].get("NetworkID")
                   for name, network in before["NetworkSettings"]["Networks"].items()),
               "NETWORK_IDENTITY_CHANGED")


def assert_model_compatible(model: dict, before: dict, service: str) -> None:
    api = model["services"][service]
    demand(api.get("container_name") == CONTAINER, "UNEXPECTED_CONTAINER_NAME")
    expected = env_map(before["Config"].get("Env") or [])
    supplied = api.get("environment") or {}
    demand(isinstance(supplied, dict), "UNRESOLVED_ENVIRONMENT")
    demand(all(k in expected and v is not None and str(v) == expected[k]
               for k, v in supplied.items()), "COMPOSE_ENVIRONMENT_DRIFT")
    # These constructs can affect other services or hide image files. Require a
    # separate reviewed deployment method if present rather than guessing.
    demand(not any(api.get(k) for k in (
        "develop", "post_start", "pre_stop", "use_api_socket", "volumes_from",
        "configs", "secrets", "external_links", "links",
    )), "UNSUPPORTED_COMPOSE_FEATURE")
    demand(not str(api.get("network_mode", "")).startswith(("service:", "container:")),
           "UNSUPPORTED_NETWORK_MODE")
    demand(not any(m.get("Type") == "volume" and not m.get("Name")
                   for m in before["Mounts"]), "UNNAMED_VOLUME")


def check_gate(gate: dict, before: dict, manifest_hash: str, now: dt.datetime,
               policy: str = "strict-idle", max_age: int = 120) -> None:
    demand(gate.get("schema") == 1, "INVALID_IDLE_GATE")
    demand(gate.get("container_id") == before["Id"] and gate.get("image_id") == before["Image"],
           "STALE_IDLE_GATE")
    demand(gate.get("manifest_sha256") == manifest_hash, "WRONG_IDLE_GATE_PAYLOAD")
    demand(policy in ("strict-idle", "controlled-restart") and gate.get("policy") == policy,
           "RESTART_POLICY_MISMATCH")
    if policy == "controlled-restart":
        demand(gate.get("notebook_agents_paused") is True, "NOTEBOOK_AGENTS_NOT_PAUSED")
        demand(isinstance(gate.get('notebook_pause_marker'), str) and
               re.fullmatch(r'vendos-colleague-auth-stop:[a-f0-9]{32}', gate['notebook_pause_marker']) is not None,
               'FRESH_OWNED_NOTEBOOK_PAUSE_REQUIRED')
        demand(isinstance(gate.get('notebook_pause_proof_sha256'), str) and
               re.fullmatch(r'[a-f0-9]{64}', gate['notebook_pause_proof_sha256']) is not None,
               'NOTEBOOK_PAUSE_PROOF_REQUIRED')
        demand(gate.get("journal_source") == "mongodb-metadata", "JOURNAL_STATE_UNKNOWN")
        demand(all(type(gate.get(k)) is int and gate[k] == 0 for k in CONTROLLED_GATE_FIELDS),
               "PENDING_BRIDGE_WORK")
    else:
        demand(gate.get("bots_coordinated_idle") is True, "BOTS_NOT_COORDINATED")
        demand(gate.get("api_admission_held") is True, "NEW_REQUESTS_NOT_HELD")
        demand(gate.get("configuration_changes_frozen") is True, "ADMIN_CHANGES_NOT_HELD")
        demand(gate.get("paused_job_source") in ("live-process-metadata", "redis-metadata"),
               "PAUSED_JOBS_UNKNOWN")
        demand(all(type(gate.get(k)) is int and gate[k] == 0 for k in ZERO_GATE_FIELDS),
               "JOBS_OR_APPROVALS_NOT_IDLE")
    try:
        observed = dt.datetime.fromisoformat(gate["observed_at_utc"].replace("Z", "+00:00"))
        age = (now - observed).total_seconds()
    except (KeyError, TypeError, ValueError):
        raise Refusal("INVALID_IDLE_GATE") from None
    demand(0 <= age <= max_age, "STALE_IDLE_GATE")


def validate_env_patch(before: dict, patch: dict) -> None:
    demand(patch == ENV_PATCH, 'UNAUTHORIZED_ENVIRONMENT_PATCH')
    demand(not set(patch).intersection(env_map(before['Config'].get('Env') or [])),
           'ALLOWLIST_ENVIRONMENT_ALREADY_PRESENT')


def engine_create_payload(before: dict, image: str, env_patch: dict | None = None) -> dict:
    host = before["HostConfig"]
    demand(host.get("NetworkMode") not in ("host", "none", "bridge") and
           not str(host.get("NetworkMode", "")).startswith("container:"), "UNSUPPORTED_NETWORK_MODE")
    demand(not any(str(host.get(key, "")).startswith("container:")
                   for key in ("IpcMode", "PidMode", "UTSMode")), "UNSUPPORTED_SHARED_NAMESPACE")
    demand(not host.get("AutoRemove") and not host.get("Links") and not host.get("VolumesFrom"),
           "UNSUPPORTED_CONTAINER_LIFECYCLE")
    demand(not before["Config"].get("MacAddress"), "STATIC_MAC_UNSUPPORTED")
    endpoints = {}
    for name, endpoint in before["NetworkSettings"]["Networks"].items():
        demand(not endpoint.get("IPAMConfig") and not endpoint.get("Links"), "STATIC_NETWORK_UNSUPPORTED")
        endpoints[name] = {
            "Aliases": [a for a in (endpoint.get("Aliases") or [])
                        if a not in (before["Id"], before["Id"][:12])],
            "DriverOpts": endpoint.get("DriverOpts"),
            "GwPriority": endpoint.get("GwPriority", 0),
        }
    config = dict(before["Config"])
    config["Image"] = image
    if env_patch is not None:
        validate_env_patch(before, env_patch)
        config['Env'] = list(config.get('Env') or []) + [k + '=' + v for k, v in env_patch.items()]
    return {**config, "HostConfig": host, "NetworkingConfig": {"EndpointsConfig": endpoints}}


class DockerSocket(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=60)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/var/run/docker.sock")


def create_stopped(commands: Commands, before: dict, image: str, name: str, env_patch: dict | None = None) -> str:
    demand(re.fullmatch(r"LibreChat-API-vendos-[a-z0-9-]+", name) is not None, "INVALID_CANDIDATE_NAME")
    payload = engine_create_payload(before, image, env_patch)
    version = commands.run(["docker", "version", "--format", "{{.Server.APIVersion}}" ]).strip()
    demand(re.fullmatch(r"1\.[0-9]{2,3}", version) is not None, "INVALID_ENGINE_VERSION")
    connection = DockerSocket()
    try:
        connection.request("POST", f"/v{version}/containers/create?name={name}", stable(payload).encode(),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(2000000)
        demand(response.status == 201, "ENGINE_CREATE_FAILED")
        result = json.loads(body)
        demand(re.fullmatch(r"[0-9a-f]{64}", result.get("Id", "")) is not None, "INVALID_CANDIDATE_ID")
        return result["Id"]
    finally:
        connection.close()


def read_private_json(path: Path) -> dict:
    demand(path.is_file() and not path.is_symlink(), "UNSAFE_INPUT_FILE")
    if os.name == "posix":
        stat = path.stat()
        demand(stat.st_uid == 0 and stat.st_mode & 0o077 == 0, "INPUT_FILE_NOT_PRIVATE")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_manifest(manifest: dict) -> dict:
    demand(manifest.get('schema') == 2 and manifest.get('purpose') == 'vendos-colleague-google-auth-only',
           'WRONG_AUTH_MANIFEST')
    baseline = manifest.get('baseline_sha256', {})
    payload = manifest.get('payload_sha256', {})
    demand(set(baseline) == set(PATHS) and set(payload) == set(PAYLOAD_PATHS), 'INVALID_PAYLOAD_PATHS')
    demand(all(isinstance(v, str) and re.fullmatch(r'[a-f0-9]{64}', v)
               for v in [*baseline.values(), *payload.values()]), 'INVALID_PAYLOAD_HASHES')
    demand(baseline['vendos.cjs'] == EXPECTED_VENDOS_BASELINE, 'OWNER_APPROVAL_BASELINE_MISMATCH')
    demand(manifest.get('environment_patch') == ENV_PATCH, 'UNAUTHORIZED_ENVIRONMENT_PATCH')
    demand(manifest.get('paths') == PAYLOAD_PATHS, 'UNAUTHORIZED_FILE_TARGETS')
    demand(isinstance(manifest.get('preflight_sha256'), str) and
           re.fullmatch(r'[a-f0-9]{64}', manifest['preflight_sha256']) is not None,
           'PREFLIGHT_PROOF_REQUIRED')
    return baseline


def load_payload(manifest: dict, directory: Path) -> dict[str, bytes]:
    validate_manifest(manifest)
    result = {}
    for name, expected in manifest['payload_sha256'].items():
        source = directory / name
        demand(source.is_file() and not source.is_symlink() and source.stat().st_size <= 16000000,
               'UNSAFE_PAYLOAD')
        data = source.read_bytes()
        demand(digest(data) == expected, 'PAYLOAD_INTEGRITY_FAILURE')
        result[name] = data
    match = re.search(rb'sourceMappingURL=([^\s]+)', result['vendos.cjs'])
    demand(match is not None and match[1] == b'vendos.cjs.map', 'SOURCE_MAP_MISSING_OR_UNSUPPORTED')
    source_map = json.loads(result['vendos.cjs.map'])
    demand(source_map.get('version') == 3 and source_map.get('sources') and source_map.get('sourcesContent'),
           'INVALID_SOURCE_MAP')
    return result


AUTH_PROBE_JS = r"""
const m=require('/app/packages/api/dist/vendos.cjs'),crypto=require('node:crypto');
if(['createVendosBriefing','isVendosDecisionText','isVerifiedGoogleEmailException','isSameGoogleExceptionIdentity']
 .some(k=>typeof m[k]!=='function')) process.exit(32);
const email='fixture@example.invalid',h=crypto.createHash('sha256').update(email).digest('hex');
const good={provider:'google',email,emailVerified:true,googleId:'test-only-google-id'};
if(!m.isVerifiedGoogleEmailException(good,h)||m.isVerifiedGoogleEmailException({...good,emailVerified:false},h)
 ||m.isVerifiedGoogleEmailException({...good,provider:'local'},h)||!m.isSameGoogleExceptionIdentity(good,good)
 ||m.isSameGoogleExceptionIdentity({...good,googleId:'other'},good)) process.exit(33);
"""

NOTEBOOK_UNREACHABLE_JS = r"""
const raw=process.env.VENDOS_BRIEFING_MCP_URL;
if(!raw)process.exit(44);
let u;try{u=new URL('/health',raw);}catch{process.exit(44);}
if(!['http:','https:'].includes(u.protocol)||u.username||u.password)process.exit(44);
const transport=require(u.protocol==='http:'?'node:http':'node:https');
const req=transport.get(u,response=>{response.resume();process.exitCode=45;});
req.setTimeout(3000,()=>{req.destroy();process.exitCode=46;});
req.on('error',e=>{if(['ECONNREFUSED','ECONNRESET'].includes(e.code))process.stdout.write('{"unreachable":true}');else process.exitCode=46;});
"""


def verify_notebook_paused(commands: Commands) -> None:
    result = json.loads(commands.run(['docker', 'exec', CONTAINER, 'node', '-e', NOTEBOOK_UNREACHABLE_JS], 10))
    demand(result == {'unreachable': True}, 'NOTEBOOK_STILL_REACHABLE_OR_UNKNOWN')


class Commands:
    def __init__(self, backup: Path):
        self.backup = backup
        self.serial = 0

    def run(self, args: list[str], timeout: int = 60) -> str:
        self.serial += 1
        result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        # Never allow Docker/Compose errors, environment values or config into
        # public CI output. Diagnostics remain root-only on the host.
        (self.backup / f"command-{self.serial:03d}.stderr").write_bytes(result.stderr)
        demand(result.returncode == 0, "COMMAND_FAILED")
        return result.stdout.decode("utf-8")

    def inspect(self, target: str = CONTAINER) -> dict:
        return json.loads(self.run(["docker", "inspect", target]))[0]

    def container_exists(self, container_id: str) -> bool:
        demand(re.fullmatch(r"[0-9a-f]{64}", container_id) is not None, "INVALID_CANDIDATE_ID")
        connection = DockerSocket()
        try:
            connection.request("GET", f"/containers/{container_id}/json")
            response = connection.getresponse()
            response.read(2000000)
            demand(response.status in (200, 404), "CONTAINER_EXISTENCE_UNKNOWN")
            return response.status == 200
        finally:
            connection.close()


METRICS_JS = r"""
const http = require('node:http');
if (!process.env.METRICS_SECRET) process.exit(21);
const request = http.get({hostname:'127.0.0.1',port:3080,path:'/metrics',
  headers:{Authorization:'Bearer '+process.env.METRICS_SECRET}}, response => {
  if (response.statusCode !== 200) { response.resume(); process.exitCode=22; return; }
  let body=''; response.on('data', data => { body+=data; if(body.length>2000000) request.destroy(); });
  response.on('end', () => {
    const names=['generation_jobs_in_flight','sse_streams_in_flight','http_requests_in_flight'];
    const result={};
    for(const name of names) {
      if(!body.includes('# TYPE '+name+' gauge')) { process.exitCode=23; return; }
      const samples=body.split('\n').filter(line=>line.startsWith(name+'{')||line.startsWith(name+' '));
      if(name==='generation_jobs_in_flight' && !samples.length) { process.exitCode=24; return; }
      result[name]=0;
      for(const line of samples) {
        if(name==='http_requests_in_flight' && /path="\/(metrics|health)"/.test(line)) continue;
        const value=Number(line.trim().split(/\s+/).pop());
        if(!Number.isFinite(value)||value<0) { process.exitCode=25; return; }
        result[name]+=value;
      }
    }
    process.stdout.write(JSON.stringify(result));
  });
});
request.setTimeout(5000,()=>request.destroy());
request.on('error',()=>{process.exitCode=26;});
"""

FILES_JS = r"""
const fs=require('node:fs'),crypto=require('node:crypto');
const files=JSON.parse(process.argv[1]),out={};
for(const [name,path] of Object.entries(files)) {
  const stat=fs.statSync(path);
  if(fs.realpathSync(path)!==path||!stat.isFile()||stat.size>16000000) process.exit(31);
  out[name]={sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex'),
    uid:stat.uid,gid:stat.gid,mode:stat.mode & 511};
}
process.stdout.write(JSON.stringify(out));
"""

MONGO_JS = r"""
const mongoose=require('mongoose');
const client=new mongoose.mongo.MongoClient(process.env.MONGO_URI,{
  serverSelectionTimeoutMS:5000,connectTimeoutMS:5000,socketTimeoutMS:7000});
(async()=>{try{
  await client.connect();const db=client.db(),options={maxTimeMS:5000};
  if(db.databaseName!=='LibreChat') throw new Error();
  const values=await Promise.all([
    db.collection('vendos_briefing_approvals').countDocuments({state:'pending'},options),
    db.collection('vendos_briefing_draft_decisions').countDocuments({state:'pending'},options),
    db.collection('vendos_briefing_leases').countDocuments({until:{$gt:new Date()}},options),
    db.collection('vendos_briefing_deliveries').countDocuments({ackedAt:{$exists:false}},options)]);
  process.stdout.write(JSON.stringify(Object.fromEntries(
    ['pending_execution_approvals','pending_draft_decisions','unexpired_bridge_leases','unacknowledged_deliveries']
      .map((key,index)=>[key,values[index]]))));
}catch{process.exitCode=41;}finally{await client.close();}})();
"""


def fresh_journal_counts(commands: Commands) -> dict:
    values = json.loads(commands.run(["docker", "exec", CONTAINER, "node", "-e", MONGO_JS], 20))
    demand(isinstance(values, dict) and set(values) == set(CONTROLLED_GATE_FIELDS), "JOURNAL_STATE_UNKNOWN")
    demand(all(type(value) is int and value == 0 for value in values.values()), "PENDING_BRIDGE_WORK")
    return values


def restart_argument(before: dict) -> str:
    policy = before["HostConfig"]["RestartPolicy"]
    name = policy["Name"] or "no"
    demand(name in ("no", "always", "unless-stopped", "on-failure"), "UNSUPPORTED_RESTART_POLICY")
    return f"on-failure:{policy['MaximumRetryCount']}" if name == "on-failure" and policy.get("MaximumRetryCount") else name


def remove_owned_candidate(commands: Commands, candidate_id: str) -> None:
    try:
        commands.run(["docker", "rm", "--force", candidate_id])
    except (Refusal, subprocess.TimeoutExpired):
        demand(not commands.container_exists(candidate_id), "CANDIDATE_REMOVAL_FAILED")


def activate_candidate(commands: Commands, before: dict, candidate_id: str,
                       overlay_id: str, retained_name: str, health_check=None,
                       env_patch: dict | None = None) -> None:
    health_check = health_check or verify_health
    policy = restart_argument(before)
    (commands.backup / "cutover-started").write_text("yes", encoding="ascii")
    try:
        commands.run(["docker", "stop", "--time", "70", before["Id"]], 90)
        # A retained always-restart container must not run alongside the new API
        # when the Docker daemon next restarts.
        commands.run(["docker", "update", "--restart", "no", before["Id"]])
        commands.run(["docker", "rename", before["Id"], retained_name])
        commands.run(["docker", "rename", candidate_id, CONTAINER])
        commands.run(["docker", "start", candidate_id])
        health_check(commands)
        assert_parity(before, commands.inspect(candidate_id), overlay_id, env_patch=env_patch)
    except BaseException:
        try:
            remove_owned_candidate(commands, candidate_id)
            original = commands.inspect(before["Id"])
            demand(original["Name"] in ("/" + CONTAINER, "/" + retained_name), "ORIGINAL_CONTAINER_RENAMED")
            if original["Name"] != "/" + CONTAINER:
                commands.run(["docker", "rename", before["Id"], CONTAINER])
            commands.run(["docker", "update", "--restart", policy, before["Id"]])
            commands.run(["docker", "start", before["Id"]])
            assert_parity(before, commands.inspect(before["Id"]), before["Image"])
            health_check(commands)
            (commands.backup / "rolled-back").write_text("yes", encoding="ascii")
        except BaseException:
            (commands.backup / "rollback-needs-operator").write_text("yes", encoding="ascii")
            raise Refusal("ROLLBACK_NEEDS_OPERATOR") from None
        raise Refusal("DEPLOYMENT_FAILED_ROLLED_BACK") from None


def observe_metrics(commands: Commands, policy: str) -> dict:
    result = {"available": False, "running": None, "sse": None, "http": None}
    try:
        metrics = json.loads(commands.run(["docker", "exec", CONTAINER, "node", "-e", METRICS_JS], 15))
        demand(isinstance(metrics, dict), "METRICS_UNKNOWN")
        demand(set(metrics) == {"generation_jobs_in_flight", "sse_streams_in_flight",
                                "http_requests_in_flight"}, "METRICS_UNKNOWN")
        demand(all(type(v) in (int, float) and 0 <= v < 100000000 for v in metrics.values()),
               "METRICS_UNKNOWN")
        result = {"available": True, "running": metrics["generation_jobs_in_flight"],
                  "sse": metrics["sse_streams_in_flight"], "http": metrics["http_requests_in_flight"]}
    except (Refusal, json.JSONDecodeError, subprocess.TimeoutExpired, TypeError):
        if policy != "controlled-restart":
            raise Refusal("METRICS_UNKNOWN") from None
    if policy != "controlled-restart":
        demand(result["available"] and all(result[k] == 0 for k in ("running", "sse", "http")),
               "SERVICE_NOT_IDLE")
    return result


def secure_directory(path: Path, new: bool = False) -> None:
    demand(path.is_absolute() and not path.is_symlink() and path.resolve() == path,
           "UNSAFE_BACKUP_DIRECTORY")
    path.mkdir(mode=0o700, parents=False, exist_ok=not new)
    stat = path.stat()
    demand(stat.st_uid == 0 and stat.st_mode & 0o077 == 0, "BACKUP_DIRECTORY_NOT_PRIVATE")


def deploy(args: argparse.Namespace) -> dict:
    demand(os.name == "posix" and os.geteuid() == 0, "ROOT_LINUX_REQUIRED")
    os.umask(0o077)
    def interrupted(_number: int, _frame: object) -> None:
        raise Refusal("INTERRUPTED")
    signal.signal(signal.SIGTERM, interrupted)
    import fcntl
    secure_directory(BACKUP_ROOT)
    lock = (BACKUP_ROOT / "deployment.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Refusal("DEPLOYMENT_ALREADY_RUNNING") from None
    manifest_path = Path(args.manifest).resolve()
    manifest_hash = digest(manifest_path.read_bytes())
    demand(manifest_hash == args.manifest_sha256, "MANIFEST_INTEGRITY_FAILURE")
    manifest = read_private_json(manifest_path)
    baseline = validate_manifest(manifest)
    payload_hashes = manifest['payload_sha256']
    payload_bytes = load_payload(manifest, Path(args.payload).resolve())
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + manifest_hash[:12]
    backup = BACKUP_ROOT / stamp
    secure_directory(backup, new=True)
    commands = Commands(backup)
    demand(not os.environ.get("DOCKER_HOST") and os.environ.get("DOCKER_CONTEXT", "default") == "default",
           "NONLOCAL_DOCKER_CONTEXT")
    demand(commands.run(["docker", "context", "show"]).strip() == "default", "NONLOCAL_DOCKER_CONTEXT")
    context = json.loads(commands.run(["docker", "context", "inspect", "default"]))[0]
    demand(context["Endpoints"]["docker"]["Host"] == "unix:///var/run/docker.sock", "NONLOCAL_DOCKER_CONTEXT")
    before = commands.inspect()
    demand(before["Name"] == "/" + CONTAINER and before["State"].get("Running") is True
           and not before["State"].get("Paused") and not before["State"].get("Restarting"),
           "UNEXPECTED_CONTAINER_STATE")
    demand(not mount_collision(before["Mounts"], list(PATHS.values())), "PAYLOAD_MOUNT_COLLISION")
    labels = before["Config"].get("Labels") or {}
    project, service = labels.get("com.docker.compose.project"), labels.get("com.docker.compose.service")
    demand(project == "librechat" and service == "api", "UNEXPECTED_COMPOSE_PROJECT")
    # Recreate directly from the active Engine configuration. Never rebuild/up
    # the stale host checkout or reinterpret its Compose/env inputs.
    engine_create_payload(before, before['Image'], ENV_PATCH)
    (backup / 'before.json').write_text(stable(before), encoding='utf-8')
    (backup / "manifest.json").write_text(stable(manifest), encoding="utf-8")
    baseline_files = json.loads(commands.run(["docker", "exec", CONTAINER, "node", "-e", FILES_JS,
                                             stable(PATHS)]))
    demand({k: v["sha256"] for k, v in baseline_files.items()} == baseline,
           "RUNTIME_BASELINE_CHANGED")
    gate_path = Path(args.gate).resolve()
    check_gate(read_private_json(gate_path), before, manifest_hash, dt.datetime.now(dt.timezone.utc), args.policy)
    fresh_journal_counts(commands)
    verify_notebook_paused(commands)
    first_metrics = observe_metrics(commands, args.policy)
    snapshot_tag = "librechat-vendos-auth-snapshot:" + stamp.lower()
    commands.run(["docker", "commit", "--pause=true", before["Id"], snapshot_tag], 120)
    snapshot_id = json.loads(commands.run(["docker", "image", "inspect", snapshot_tag]))[0]["Id"]
    demand(re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot_id) is not None, "INVALID_SNAPSHOT")
    (backup / "snapshot-id").write_text(snapshot_id, encoding="ascii")
    build = backup / "build"
    secure_directory(build, new=True)
    dockerfile = ["FROM " + snapshot_tag]
    for name in payload_hashes:
        (build / name).write_bytes(payload_bytes[name])
        demand(digest((build / name).read_bytes()) == payload_hashes[name], "PAYLOAD_CHANGED_DURING_COPY")
        # Map follows compiled JS ownership/mode; source wrappers preserve their own.
        attrs = baseline_files[name if name in baseline_files else "vendos.cjs"]
        dockerfile.append(f"COPY --chown={attrs['uid']}:{attrs['gid']} --chmod={attrs['mode']:04o} {name} {PATHS[name]}")
    (build / "Dockerfile").write_text("\n".join(dockerfile) + "\n", encoding="ascii")
    overlay_tag = "librechat-vendos-colleague-auth:" + stamp.lower()
    commands.run(["docker", "build", "--pull=false", "--network=none", "--tag", overlay_tag,
                  str(build)], 180)
    overlay_id = json.loads(commands.run(["docker", "image", "inspect", overlay_tag]))[0]["Id"]
    (backup / "overlay-id").write_text(overlay_id, encoding="ascii")
    built_files = json.loads(commands.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--no-healthcheck",
                                          "--entrypoint", "node", overlay_tag, "-e", FILES_JS,
                                          stable({k: PATHS[k] for k in payload_hashes})]))
    demand({k: v["sha256"] for k, v in built_files.items()} == payload_hashes, "BUILT_HASH_MISMATCH")
    demand(all(all(built_files[k][attribute] == baseline_files[k if k in baseline_files else "vendos.cjs"][attribute]
                   for attribute in ("uid", "gid", "mode")) for k in payload_hashes), "BUILT_FILE_ATTRIBUTES_CHANGED")
    for name in (name for name in PAYLOAD_PATHS if name != "vendos.cjs.map"):
        commands.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--no-healthcheck",
                      "--entrypoint", "node", overlay_tag, "--check", PATHS[name]])
    commands.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--no-healthcheck',
                  '--entrypoint', 'node', overlay_tag, '-e', AUTH_PROBE_JS])
    preserved = json.loads(commands.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                          '--no-healthcheck', '--entrypoint', 'node', overlay_tag, '-e', FILES_JS,
                          stable(PRESERVED_PATHS)]))
    demand({k: v['sha256'] for k, v in preserved.items()} == {k: baseline[k] for k in PRESERVED_PATHS},
           'OWNER_APPROVAL_OR_CREDENTIAL_WRAPPER_CHANGED')
    (backup / 'deployment.json').write_text(stable({
        'manifest_sha256': manifest_hash, 'snapshot_tag': snapshot_tag, 'snapshot_id': snapshot_id,
        'overlay_tag': overlay_tag, 'overlay_id': overlay_id, 'environment_patch': ENV_PATCH,
        'original_container_id': before['Id'], 'original_image_id': before['Image'],
    }), encoding='utf-8')
    current = commands.inspect()
    demand(current["Id"] == before["Id"] and current["Image"] == before["Image"], "CONTAINER_CHANGED")
    demand(canonical_inspect(current) == canonical_inspect(before), "CONFIGURATION_CHANGED")
    gate = read_private_json(gate_path)
    check_gate(gate, before, manifest_hash, dt.datetime.now(dt.timezone.utc), args.policy,
               max_age=600 if args.policy == "controlled-restart" else 120)
    last_metrics = observe_metrics(commands, args.policy)
    (backup / "restart-evidence.json").write_text(stable({
        "policy": args.policy, "gate": gate,
        "first_metrics": first_metrics, "cutover_metrics": last_metrics,
    }), encoding="utf-8")
    candidate_name = "LibreChat-API-vendos-candidate-" + stamp.lower()
    retained_name = "LibreChat-API-vendos-rollback-" + stamp.lower()
    candidate_id = create_stopped(commands, before, overlay_id, candidate_name, ENV_PATCH)
    (backup / "candidate-id").write_text(candidate_id, encoding="ascii")
    (backup / "retained-name").write_text(retained_name, encoding="ascii")
    try:
        after = commands.inspect(candidate_id)
        demand(not after["State"].get("Running"), "CANDIDATE_STARTED_EARLY")
        assert_parity(before, after, overlay_id, candidate_name, ENV_PATCH)
        verify_networks(commands, before)
        verify_notebook_paused(commands)
        current_files = json.loads(commands.run(["docker", "exec", CONTAINER, "node", "-e", FILES_JS, stable(PATHS)]))
        demand({k: v["sha256"] for k, v in current_files.items()} == baseline, "RUNTIME_BASELINE_CHANGED")
        if args.policy == "controlled-restart":
            (backup / "fresh-journal-counts.json").write_text(stable(fresh_journal_counts(commands)), encoding="utf-8")
    except BaseException:
        remove_owned_candidate(commands, candidate_id)
        raise
    def check_started(commands: Commands) -> None:
        verify_health(commands)
        expected_hashes = {**baseline, **payload_hashes} if commands.inspect()["Image"] == overlay_id else baseline
        actual = json.loads(commands.run(["docker", "exec", CONTAINER, "node", "-e", FILES_JS,
                                         stable({k: PATHS[k] for k in expected_hashes})]))
        demand(all(actual[k]["sha256"] == v for k, v in expected_hashes.items()), "DEPLOYED_HASH_MISMATCH")
    activate_candidate(commands, before, candidate_id, overlay_id, retained_name, check_started, ENV_PATCH)
    (backup / "complete").write_text("yes", encoding="ascii")
    return {"status": "deployed", "health_ok": True, "configuration_parity_except_exact_env_addition": True,
            "payload_integrity": True, "rollback_snapshot_retained": True, "original_container_retained": True,
            "exact_email_hash_allowlist_added": True, "owner_approval_preserved": True,
            "restart_policy": args.policy, "metrics_available": last_metrics["available"],
            "running_jobs_observed": last_metrics["running"]}


def verify_networks(commands: Commands, before: dict) -> None:
    for name, expected in before["NetworkSettings"]["Networks"].items():
        actual = json.loads(commands.run(["docker", "network", "inspect", name]))[0]
        demand(actual["Id"] == expected["NetworkID"], "NETWORK_IDENTITY_CHANGED")


def verify_health(commands: Commands) -> None:
    for _ in range(30):
        state = commands.inspect()
        if state["State"].get("Running"):
            try:
                code = commands.run(["docker", "exec", CONTAINER, "curl", "--silent", "--output",
                                     "/dev/null", "--write-out", "%{http_code}", "--max-time", "2",
                                     "http://127.0.0.1:3080/health"], 5)
                if code == "200":
                    return
            except Refusal:
                pass
        time.sleep(2)
    raise Refusal("HEALTH_CHECK_FAILED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--gate")
    parser.add_argument("--policy", choices=("controlled-restart",), default="controlled-restart")
    args = parser.parse_args()
    try:
        if args.execute:
            demand(bool(args.gate), 'IDLE_GATE_REQUIRED')
            result = deploy(args)
        else:
            manifest_path = Path(args.manifest).resolve()
            demand(digest(manifest_path.read_bytes()) == args.manifest_sha256, 'MANIFEST_INTEGRITY_FAILURE')
            manifest = read_private_json(manifest_path)
            load_payload(manifest, Path(args.payload).resolve())
            result = {'status': 'payload_verified_not_deployed', 'file_count': len(PAYLOAD_PATHS),
                      'environment_additions': 1, 'docker_called': False}
    except Refusal as error:
        print(stable({"status": "stopped", "error_code": error.code}))
        return 1
    except BaseException:
        print(stable({"status": "stopped", "error_code": "UNEXPECTED_FAILURE"}))
        return 1
    print(stable(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
