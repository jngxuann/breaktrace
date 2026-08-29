"""Bounded repository and sandbox-local application discovery."""

import ast
import json
import os
import re
import shlex
import uuid
from urllib.parse import urlparse

from models import (
    APIReference,
    ApplicationContext,
    ApplicationCapability,
    DataResource,
    DiscoveredRoute,
    ExternalService,
    FrontendRoute,
    IdentityInput,
    ResourceOwnership,
    SeedEntity,
    StorageResource,
    StorageSignal,
)
from targets import TargetAdapter

TARGET_TEST_CLIENT_SOURCE = r'''
import json, os, sys, time, urllib.error, urllib.request
BASE = os.getenv("BREAKTRACE_TARGET_ORIGIN", "http://127.0.0.1:3000")
ALLOWED_METHODS = ("GET", "DELETE", "OPTIONS")
def _parse_body(raw):
    try: return json.loads(raw)
    except ValueError: return raw[:4000]
def _header_map(msg):
    out = {}
    for key in msg.keys():
        values = msg.get_all(key) or []
        out[key.lower()] = values[0] if len(values) == 1 else values
    return out
def http_request(method, path, timeout=10, headers=None):
    req = urllib.request.Request(BASE + path, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _parse_body(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, _parse_body(exc.read().decode("utf-8", "replace"))
    except Exception as exc: return -1, {"error": str(exc)}
def http_request_with_headers(method, path, headers=None):
    req = urllib.request.Request(BASE + path, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, _header_map(resp.headers), _parse_body(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        return exc.code, _header_map(exc.headers), _parse_body(raw)
    except Exception as exc: return -1, {}, {"error": str(exc)}
def env_headers():
    out = {}
    for line in os.getenv("BREAKTRACE_TARGET_HEADERS", "").splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip()
    return out
def wait_ready(seconds=120):
    deadline = time.time() + seconds
    while time.time() < deadline:
        status, _ = http_request("GET", "/")
        if status == 200: return True
        time.sleep(2)
    return False
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--wait":
        print("ready" if wait_ready() else "not-ready")
    elif len(sys.argv) > 1 and sys.argv[1] == "--probe":
        results = []
        for path in sys.argv[2].split("|"):
            status, _ = http_request("GET", path)
            results.append({"path": path, "status": status})
        print(json.dumps(results))
    elif len(sys.argv) > 1 and sys.argv[1] == "--headers":
        method, target = "GET", "/"
        if len(sys.argv) > 2 and sys.argv[2] in ALLOWED_METHODS:
            method = sys.argv[2]
            if len(sys.argv) > 3: target = sys.argv[3]
        extra_headers = {}
        for line in os.getenv("BREAKTRACE_TARGET_HEADERS", "").splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                extra_headers[key.strip()] = value.strip()
        status, headers, body = http_request_with_headers(method, target, extra_headers)
        print(json.dumps({"status": status, "headers": headers, "body": body}))
    else:
        method, target = "GET", "/"
        if len(sys.argv) > 1 and sys.argv[1] in ("GET", "DELETE"):
            method = sys.argv[1]
            if len(sys.argv) > 2: target = sys.argv[2]
        elif len(sys.argv) > 1: target = sys.argv[1]
        status, body = http_request(method, target, headers=env_headers() or None)
        print(json.dumps({"status": status, "body": body}))
'''


def exec_in_sandbox(sandbox, command: str, timeout: int = 60, env: dict | None = None) -> str:
    result = sandbox.process.exec(command, timeout=timeout, env=env)
    output = (result.result or "").strip()
    if result.exit_code != 0:
        raise RuntimeError(f"Command failed with exit code {result.exit_code}: {output or '(no output)'}")
    return output

_ROUTE_RE = re.compile(r"\b(?:app|router|api)\.(?P<method>get|post|put|delete|patch)\s*\(\s*(?P<quote>['\"])(?P<path>.*?)(?P=quote)", re.IGNORECASE)

# Python stdlib http.server routes: re.fullmatch(r"/api/x/(\d+)", path).
# Used for zero-dependency demo targets and any Python stdlib web server.
_PY_HTTP_ROUTE_RE = re.compile(
    r"\b(?:re\.(?:fullmatch|match|search)|[a-zA-Z_][\w]*\.fullmatch)\s*\(\s*"
    r"[rbRB]?['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)


def _normalize_py_route(path: str) -> str:
    """Convert regex-ish Python route literals into route patterns."""
    path = re.sub(r"\(\?P<([A-Za-z_]\w*)>[^)]*\)", r":\1", path or "")
    path = re.sub(r"\(\\d\+\)", ":id", path)
    path = re.sub(r"\\d\+", ":id", path)
    path = re.sub(r"\([^)]*\)", ":id", path)
    return path


def extract_python_http_routes(source: str) -> list[tuple[str, str]]:
    """Extract GET route patterns from Python stdlib http.server style source."""
    out: list[tuple[str, str]] = []
    seen: set = set()
    for match in _PY_HTTP_ROUTE_RE.finditer(source or ""):
        raw = match.group(1)
        if not raw.startswith("/") or "://" in raw or " " in raw or "{" in raw:
            continue
        route = _normalize_py_route(raw).rstrip("/") or "/"
        if ("GET", route) not in seen:
            seen.add(("GET", route))
            out.append(("GET", route))
    return out


# ---------------------------------------------------------------------------
# Milestone 12 - conservative source understanding for authorization semantics
#
# A small, bounded parser over Python server source. It does NOT understand
# arbitrary Python. It only recognizes, conservatively:
#   1. request headers read as identity (e.g. X-Demo-User)
#   2. static, integer-keyed dict fixtures (e.g. USERS / REPORTS)
#   3. resource records that carry an owner field (ownership relationship)
#   4. the bounded numeric ids in those fixtures (seed evidence)
#
# It NEVER collects secrets, never reads environment variable values, and
# ignores anything that does not look like a tiny static literal fixture.
# ---------------------------------------------------------------------------

_PY_SECRET_TARGET_RE = re.compile(
    r"(password|passwd|secret|token|api_?key|credential|authorization|"
    r"bearer|session|private|salt|jwt|signing)",
    re.IGNORECASE,
)
_PY_HEADER_READ_RE = re.compile(
    r"(?:request\.|self\.)?headers\s*\.\s*(?:get|get_all|__getitem__|__contains__)"
    r"\s*\(\s*[\"']([A-Za-z0-9_.:()-]{1,64})[\"']"
    r"|headers\s*\[\s*[\"']([A-Za-z0-9_.:()-]{1,64})[\"']",
    re.IGNORECASE,
)
_PY_IDENTITY_HINT_RE = re.compile(
    r"(user|identity|principal|actor|member|account)", re.IGNORECASE
)
_MAX_SEED_KEYS = 25
_MAX_SEED_LABEL_LEN = 40


def _looks_like_identity_header(name: str) -> bool:
    return bool(_PY_IDENTITY_HINT_RE.search(name or ""))


def _py_int_key(node) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _py_str_const(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _py_scalar(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(
        node.value, (str, int, float, bool)
    )


def _py_record_fields(node) -> dict:
    """Map literal string/int keys of a dict literal to their values."""
    if not isinstance(node, ast.Dict):
        return {}
    out = {}
    for k, val in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and isinstance(k.value, (str, int)):
            out[str(k.value)] = val
    return out


def _py_record_owner_field(fields: dict, records) -> str:
    """Find an ownership field shared by resource records, e.g. owner_id."""
    for key in fields:
        low = key.lower()
        if "owner" in low and (low.endswith("id") or low.endswith("_id")):
            return key
        if "owner" in low:
            return key
    return ""


def analyze_python_security_semantics(records) -> dict:
    """Conservatively infer authorization semantics from Python source.

    Returns a dict of generic DISCOVERY SIGNALS (never vulnerability claims):
      {
        "identity_inputs": [ ... IdentityInput-shaped dicts ... ],
        "resource_relationships": [ ... ResourceOwnership-shaped dicts ... ],
        "seed_entities": [ ... SeedEntity-shaped dicts ... ],
      }

    Anything that is not a tiny static literal fixture (string-keyed,
    oversized, secret-like) is ignored. Env values are never read.
    """
    identity_inputs = []
    relationships = []
    seed_entities = []
    seen_identity = set()
    seen_relationship = set()
    seen_seed = set()
    principal_ids_by_name = {}    # resource name -> set of principal ids

    for rec in records or []:
        path = str(rec.get("path", ""))
        if not path.endswith(".py"):
            continue
        source = path
        src = rec.get("content", "") or ""

        # 1. Identity inputs: request headers read as identity.
        for m in _PY_HEADER_READ_RE.finditer(src):
            name = m.group(1) or m.group(2)
            if not name or name in seen_identity:
                continue
            seen_identity.add(name)
            purpose = (
                "user_identity" if _looks_like_identity_header(name)
                else "request_header"
            )
            identity_inputs.append({
                "name": name,
                "kind": "request_header",
                "purpose": purpose,
                "provenance": "repository",
                "source": source,
                "confidence": "high" if purpose == "user_identity" else "medium",
            })

        # 2. Static fixtures (integer-keyed literal dicts).
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name) or _PY_SECRET_TARGET_RE.search(target.id):
                continue
            value = node.value
            if not isinstance(value, ast.Dict) or not value.keys:
                continue
            keys_int = [_py_int_key(k) for k in value.keys]
            if not keys_int or not all(k is not None for k in keys_int) \
                    or len(keys_int) > _MAX_SEED_KEYS:
                continue
            var = target.id
            vals = value.values
            records_list = [keys_int[i] for i in range(len(keys_int))]

            # 2a. Resource fixture: dict of dicts (e.g. REPORTS = {1: {...}}).
            if vals and all(isinstance(v, ast.Dict) for v in vals):
                first_fields = _py_record_fields(vals[0])
                owner_field = _py_record_owner_field(first_fields, vals)
                ids = sorted(set(int(k) for k in keys_int))
                seed_entities.append({
                    "entity_type": var.lower(),
                    "identifiers": ids,
                    "labels": {},
                    "provenance": "repository",
                    "source": source,
                    "confidence": "high",
                })
                if owner_field and "id" in first_fields:
                    owners = {}
                    for k, val in zip(keys_int, vals):
                        fields = _py_record_fields(val)
                        oid = _py_int_key(fields.get(owner_field))
                        if oid is not None:
                            owners[int(k)] = oid
                    if owners:
                        pr_ids = sorted(set(owners.values()))
                        rel_key = (var.lower(), owner_field)
                        if rel_key not in seen_relationship:
                            seen_relationship.add(rel_key)
                            relationships.append({
                                "resource": var.lower(),
                                "resource_identifier": "id",
                                "owner_field": owner_field,
                                "identity_field": "user_id",
                                "resource_identifiers": sorted(set(ids)),
                                "principal_identifiers": pr_ids,
                                "owners": owners,
                                "provenance": "repository",
                                "source": source,
                                "confidence": "high" if len(ids) >= 2 else "low",
                            })
                            principal_ids_by_name.setdefault(var.lower(), set()).update(pr_ids)

            # 2b. Principal fixture: dict of scalars (e.g. USERS = {1: "Alice"}).
            elif vals and all(_py_scalar(v) for v in vals):
                ids = sorted(set(int(k) for k in keys_int))
                labels = {}
                for k, v in zip(keys_int, vals):
                    s = _py_str_const(v)
                    if s and len(s) <= _MAX_SEED_LABEL_LEN \
                            and not re.search(r"[\s{}=():;]", s):
                        labels[int(k)] = s
                seed_entities.append({
                    "entity_type": var.lower(),
                    "identifiers": ids,
                    "labels": labels,
                    "provenance": "repository",
                    "source": source,
                    "confidence": "high",
                })
                # Union into every ownership relationship's principal ids.
                if var.lower() in ("users", "user", "accounts", "principals"):
                    for rel in relationships:
                        if var.lower() in ("users", "user"):
                            rel["principal_identifiers"] = sorted(
                                set(rel.get("principal_identifiers", [])) | set(ids)
                            )

    # De-duplicate seed entities by type (keep the one with the most ids).
    dedup_seed = {}
    for se in seed_entities:
        t = se["entity_type"]
        if t not in dedup_seed or len(se["identifiers"]) > len(dedup_seed[t]["identifiers"]):
            dedup_seed[t] = se
    # De-duplicate relationships by (resource, owner_field).
    dedup_rel = {}
    for rel in relationships:
        k = (rel["resource"], rel["owner_field"])
        if k not in dedup_rel:
            dedup_rel[k] = rel
        else:
            dedup_rel[k]["resource_identifiers"] = sorted(
                set(dedup_rel[k]["resource_identifiers"]) | set(rel["resource_identifiers"])
            )
            dedup_rel[k]["owners"].update(rel.get("owners", {}))
            dedup_rel[k]["principal_identifiers"] = sorted(
                set(dedup_rel[k]["principal_identifiers"]) | set(rel["principal_identifiers"])
            )
    return {
        "identity_inputs": identity_inputs,
        "resource_relationships": sorted(
            dedup_rel.values(), key=lambda r: (r["resource"], r["owner_field"])
        ),
        "seed_entities": [
            dedup_seed[t] for t in sorted(dedup_seed)
        ],
    }

def parse_package_json(raw: str) -> dict:
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError): return {}

_FRAMEWORK_KEYS = {
    "express": "Express", "sequelize": "Sequelize", "angularjs": "AngularJS",
    "angular": "Angular", "socket.io": "Socket.IO", "react": "React",
    "react-dom": "React", "next": "Next.js", "vue": "Vue", "vite": "Vite",
    "@vitejs/plugin-react": "Vite", "fastify": "Fastify", "django": "Django",
    "flask": "Flask", "rails": "Rails",
}

def detect_frameworks(deps: dict) -> list[str]:
    result = []
    for name, framework in _FRAMEWORK_KEYS.items():
        if name in deps and framework not in result: result.append(framework)
    return result

def detect_framework(deps: dict) -> str:
    frameworks = detect_frameworks(deps)
    return " + ".join(frameworks) if frameworks else (deps.get("name") or "unknown")

_AUTH_SIGNAL_KEYS = ("jsonwebtoken", "express-jwt", "jwt", "passport", "bcrypt", "helmet", "cookie-parser", "express-rate-limit", "cors", "csrf", "oauth", "session", "ldap", "basic-auth", "firebase", "auth0")
def auth_signals_from_deps(deps: dict) -> list[str]:
    return sorted(k for k in _AUTH_SIGNAL_KEYS if k in deps)

def merge_package_dependencies(package: dict) -> dict:
    merged = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        values = package.get(section) or {}
        if isinstance(values, dict): merged.update(values)
    return merged

def source_language(path: str) -> str:
    return {".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".jsx": "jsx", ".json": "json", ".py": "python"}.get(os.path.splitext(path)[1].lower(), "text")

def parse_source_archive(raw: str) -> list[dict]:
    records = []
    for line in (raw or "").splitlines():
        try: record = json.loads(line)
        except (ValueError, TypeError): continue
        if not isinstance(record, dict) or not record.get("path") or not isinstance(record.get("content", ""), str): continue
        records.append({"path": str(record["path"]), "language": record.get("language") or source_language(str(record["path"])), "content": record["content"]})
    return records

# .py is included so a zero-dependency Python server declared at the
# repository root (e.g. the regression demo's app.py) is discovered.
_SOURCE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".json", ".py")
_SOURCE_ROOTS = ("src", "app", "pages", "components", "lib", "services", "utils")

def walk_repository_source(sandbox, adapter: TargetAdapter) -> tuple[list[dict], dict]:
    script = r'''import json, os
root=os.environ["BREAKTRACE_REPO_ROOT"]
allowed={".ts",".tsx",".js",".jsx",".json",".py"}; roots=["src","app","pages","components","lib","services","utils"]
max_files=300; max_file_bytes=200000; max_total_bytes=2000000; count=0; total=0; seen=set()
def emit(path):
 global count,total
 if count>=max_files or path in seen: return
 suffix=os.path.splitext(path)[1].lower()
 if suffix not in allowed: return
 try:
  size=os.path.getsize(path)
  if size>max_file_bytes or total+size>max_total_bytes: return
  raw=open(path,"rb").read(max_file_bytes+1)
  if len(raw)>max_file_bytes or b"\x00" in raw: return
  text=raw.decode("utf-8")
 except (OSError,UnicodeError): return
 seen.add(path); count+=1; total+=len(raw)
 print(json.dumps({"path":os.path.relpath(path,root).replace(os.sep,"/"),"language":suffix[1:],"content":text},ensure_ascii=False))
for name in ("package.json","package-lock.json"):
 path=os.path.join(root,name)
 if os.path.isfile(path): emit(path)
# A single top-level Python entry file (app.py/server.py/main.py) enables
# discovery of repository-root Python servers (e.g. the regression demo).
for name in sorted(os.listdir(root)):
 if name.endswith(".py"):
  emit(os.path.join(root,name))
for dirname in roots:
 base=os.path.join(root,dirname)
 if not os.path.isdir(base): continue
 for current,dirs,files in os.walk(base):
  dirs[:]=[d for d in dirs if d not in {"node_modules",".git","dist","build","coverage",".next","out"} and not d.startswith(".")]
  for name in sorted(files):
   emit(os.path.join(current,name))
   if count>=max_files: break
  if count>=max_files: break
 if count>=max_files: break
'''
    raw = exec_in_sandbox(sandbox, f"cd {adapter.repo_dir} && python -c {shlex.quote(script)}", timeout=120, env={"BREAKTRACE_REPO_ROOT": adapter.repo_dir})
    records = parse_source_archive(raw)
    extensions = {ext[1:]: 0 for ext in _SOURCE_EXTENSIONS}
    for record in records:
        ext = os.path.splitext(record["path"])[1].lower().lstrip(".")
        if ext in extensions: extensions[ext] += 1
    diagnostics = {"repository_root": adapter.repo_dir, "package_json_found": any(r["path"] == "package.json" for r in records), "package_json_parsed": False, "source_files_found": len(records), "source_files_scanned": len(records), "extensions": extensions}
    return records, diagnostics

def extract_routes_from_source(source: str) -> list[tuple[str, str]]:
    seen=set(); out=[]
    for match in _ROUTE_RE.finditer(source or ""):
        method=match.group("method").lower(); path=(match.group("path") or "").strip()
        if not path.startswith("/") or "${" in path or "{" in path: continue
        path=path.rstrip("/") or "/"
        if (method,path) not in seen: seen.add((method,path)); out.append((method,path))
    return out

def security_components_from_file_list(lines: list[str]) -> list[str]:
    pattern=re.compile(r"(insecurity|auth|token|jwt|user|admin|login|registration|password|security|rate|helmet|session|role)", re.IGNORECASE)
    return sorted({name for name in lines if name and pattern.search(name)})

_FRONTEND_ROUTE_DEF_RE = re.compile(r"(createBrowserRouter|createHashRouter|BrowserRouter|useRoutes|<Route)", re.IGNORECASE)
_FRONTEND_PATH_LITERAL_RE = re.compile(r"path\s*[:=]\s*[\"'](/[^\"']*)[\"']")
_FRONTEND_API_CALL_RE = re.compile(r"\b(fetch|axios|createClient|supabase)\b", re.IGNORECASE)
_FRONTEND_ABSOLUTE_URL_RE = re.compile(r"[\"'](https?://[^\"']+)[\"']")
_FRONTEND_RELATIVE_API_RE = re.compile(r"(?:fetch|axios\s*\.(?:get|post|put|patch|delete))\s*\(\s*[\"'](/[^\"']+)[\"']", re.IGNORECASE | re.DOTALL)
_FRONTEND_SUPABASE_TABLE_RE = re.compile(r"\bsupabase\s*\.\s*from\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE | re.DOTALL)
_FRONTEND_SUPABASE_STORAGE_RE = re.compile(r"(?:supabase|[A-Za-z_$][\w$]*)\s*\.\s*storage\s*\.\s*from\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE | re.DOTALL)
_FRONTEND_SUPABASE_OPERATION_RE = re.compile(r"\.\s*(select|insert|update|upsert|delete|rpc)\s*\(", re.IGNORECASE)
_FRONTEND_STORAGE_OPERATION_RE = re.compile(r"\.\s*(upload|download|remove|list|move|copy)\s*\(", re.IGNORECASE)
_FRONTEND_AUTH_USAGE_RE = re.compile(r"(?:supabase|[A-Za-z_$][\w$]*)\s*\.\s*auth\s*\.\s*(getSession|getUser|signIn\w*|signUp\w*|signOut|onAuthStateChange)", re.IGNORECASE | re.DOTALL)
_FRONTEND_AUTH_GENERIC_RE = re.compile(r"\b(getSession|getUser|signIn\w*|signUp\w*|signOut|onAuthStateChange)\b|authorization\s*[:=]|bearer\s+", re.IGNORECASE)
_FRONTEND_ENV_RE = re.compile(r"(?:import\.meta\.env|process\.env)\.([A-Z0-9_]+)")
_FRONTEND_STORAGE_RE = re.compile(r"(localStorage|sessionStorage)\.(setItem|getItem)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
# Query-parameter read evidence: searchParams.get('x'), params.has("y"),
# url.searchParams.getAll('z'), new URLSearchParams(location.search).get('w'),
# and router-style query reads. Only names actually READ from the URL in
# source are recorded - never invented.
_FRONTEND_QUERY_PARAM_READ_RE = re.compile(
    r"(?:searchParams|params|queryParams?|url\.searchParams|" 
    r"window\.location\.[a-zA-Z]*search[a-zA-Z]*)"
    r"\s*\.\s*(?:get|getAll|getNumber|has)\s*\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]",
    re.IGNORECASE,
)
_FRONTEND_QUERY_PARAM_CTOR_RE = re.compile(
    r"new\s+URLSearchParams\s*\(\s*[^)]*\)\s*\.\s*(?:get|getAll|getNumber|has)\s*\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]",
    re.IGNORECASE,
)
_FRONTEND_LOCATION_SEARCH_RE = re.compile(r"location\.search|window\.location\.search")

def _source_records_to_lines(records): return [(r["path"], 1, r["content"]) for r in records]
def parse_frontend_lines(output): return [(m.group(1), int(m.group(2)), m.group(3)) for line in (output or "").splitlines() if (m := re.match(r"^(.*?):(\d+):(.*)$", line))]

def extract_frontend_routes_from_lines(lines):
    out=[]; seen=set()
    for _,_,content in lines:
        if not _FRONTEND_ROUTE_DEF_RE.search(content): continue
        for m in _FRONTEND_PATH_LITERAL_RE.finditer(content):
            path=m.group(1).rstrip("/") or "/"
            if path not in seen: seen.add(path); out.append(path)
    return out

def extract_api_references_from_lines(lines):
    refs=[]; seen=set()
    for path,line,content in lines:
        if not _FRONTEND_API_CALL_RE.search(content): continue
        for m in _FRONTEND_ABSOLUTE_URL_RE.finditer(content):
            key=("external",m.group(1))
            if key not in seen: seen.add(key); refs.append({"url":m.group(1),"kind":"external","source":f"{path}:{line}"})
        for m in _FRONTEND_RELATIVE_API_RE.finditer(content):
            key=("relative",m.group(1))
            if key not in seen: seen.add(key); refs.append({"url":m.group(1),"kind":"relative","source":f"{path}:{line}"})
        for m in _FRONTEND_SUPABASE_TABLE_RE.finditer(content):
            key=("supabase_table",m.group(1))
            if key not in seen: seen.add(key); refs.append({"url":m.group(1),"kind":"supabase_table","source":f"{path}:{line}"})
    return refs

def extract_environment_references_from_lines(lines):
    out=[]; seen=set()
    for _,_,content in lines:
        for m in _FRONTEND_ENV_RE.finditer(content):
            if m.group(1) not in seen: seen.add(m.group(1)); out.append(m.group(1))
    return out

def extract_storage_signals_from_lines(lines):
    out=[]; seen=set()
    for path,line,content in lines:
        for m in _FRONTEND_STORAGE_RE.finditer(content):
            key=(m.group(1),m.group(3))
            if key not in seen: seen.add(key); out.append({"storage_type":m.group(1),"key":m.group(3),"source":f"{path}:{line}"})
    return out

def extract_query_parameters_from_lines(lines):
    """Return the query parameter names actually read from the URL in source.

    Only parameters evidenced by concrete read patterns are recorded. A
    bare `location.search` present with no named read does not produce a
    specific parameter name (there is nothing to evidence), so it is ignored
    here - names are never guessed.
    """
    out=[]; seen=set()
    for path,line,content in lines:
        for regex in (_FRONTEND_QUERY_PARAM_READ_RE, _FRONTEND_QUERY_PARAM_CTOR_RE):
            for m in regex.finditer(content):
                name=m.group(1)
                if name not in seen: seen.add(name); out.append({"name":name,"source":f"{path}:{line}"})
    return out

def extract_supabase_resources(records):
    data={}; storage={}; auth=[]; sdk_sources=[]
    for record in records:
        path=record["path"]; content=record["content"]; normalized=re.sub(r"\s+"," ",content)
        if re.search(r"@supabase/supabase-js|createClient\s*\(",content,re.IGNORECASE): sdk_sources.append(path)
        for m in _FRONTEND_SUPABASE_TABLE_RE.finditer(content):
            prefix = re.sub(r"\s+", "", content[max(0, m.start() - 30):m.start()]).lower()
            if prefix.endswith(".storage"):
                continue
            name=m.group(1).strip(); window=normalized[:]
            ops=sorted({op.lower() for op in _FRONTEND_SUPABASE_OPERATION_RE.findall(window)})
            item=data.setdefault(name,{"name":name,"service":"supabase","operations":[],"source":path}); item["operations"]=sorted(set(item["operations"])|set(ops))
        for m in _FRONTEND_SUPABASE_STORAGE_RE.finditer(content):
            name=m.group(1).strip(); window=normalized[:]
            ops=sorted({op.lower() for op in _FRONTEND_STORAGE_OPERATION_RE.findall(window)})
            item=storage.setdefault(name,{"name":name,"service":"supabase","operations":[],"source":path}); item["operations"]=sorted(set(item["operations"])|set(ops))
        for m in _FRONTEND_AUTH_USAGE_RE.finditer(content):
            signal=f"Supabase auth usage: {m.group(1)}"
            if signal not in auth: auth.append(signal)
        if _FRONTEND_AUTH_GENERIC_RE.search(content):
            signal=f"Authentication-related source usage in {path}"
            if signal not in auth: auth.append(signal)
    return list(data.values()), list(storage.values()), sdk_sources, auth

def extract_capabilities(records, data_resources, storage_resources):
    result={}
    patterns=(("report submission",r"\b(submit|create|insert)\b.*\breports?\b|\breports?\b.*\b(insert|submit)\b"),("report viewing",r"\b(select|view|load|fetch)\b.*\breports?\b|\breports?\b.*\b(select|view|load)\b"),("evidence upload",r"\b(upload|file|evidence)\b"),("rewards viewing",r"\brewards?\b"))
    for record in records:
        content=re.sub(r"\s+"," ",record["content"])
        for name,pattern in patterns:
            if re.search(pattern,content,re.IGNORECASE): result.setdefault(name,{"name":name,"source":record["path"]})
    for resource in data_resources:
        if resource["name"].lower()=="reports":
            for op in resource.get("operations",[]):
                name="report submission" if op in {"insert","upsert"} else "report viewing" if op=="select" else None
                if name: result.setdefault(name,{"name":name,"source":resource.get("source","")})
    for resource in storage_resources:
        if "upload" in resource.get("operations",[]): result.setdefault("evidence upload",{"name":"evidence upload","source":resource.get("source","")})
    return list(result.values())

def extract_external_services(api_references):
    services=set()
    for ref in api_references:
        if ref["kind"]!="external": continue
        try: host=urlparse(ref["url"]).hostname or ""
        except ValueError: host=""
        if host.endswith(".supabase.co"): services.add("supabase")
        elif host.endswith(".firebaseapp.com"): services.add("firebase")
        elif host: services.add(host)
    return sorted(services)

def inspect_repository(sandbox, adapter):
    records, diagnostics=walk_repository_source(sandbox,adapter)
    package_record=next((r for r in records if r["path"]=="package.json"),None)
    package=parse_package_json(package_record["content"] if package_record else "")
    diagnostics["package_json_parsed"]=bool(package_record and package)
    deps=merge_package_dependencies(package); lines=_source_records_to_lines(records); routes=[]
    underscored = [e for e in _SOURCE_EXTENSIONS if e != ".json"]
    for path,_,content in lines:
        if path.endswith(tuple(underscored)):
            routes.extend(extract_routes_from_source(content))
            routes.extend(extract_python_http_routes(content))
    models=[]
    for record in records:
        if "/models/" in f"/{record['path']}" and record["path"].endswith(_SOURCE_EXTENSIONS[:-1]):
            name=os.path.splitext(os.path.basename(record["path"]))[0]
            if name and name not in models: models.append(name)
    frameworks=detect_frameworks(deps)
    semantic = analyze_python_security_semantics(records)
    return {"deps":deps,"package":package,"framework":" + ".join(frameworks) if frameworks else "unknown","frameworks":frameworks,"routes":list(dict.fromkeys(routes)),"models":models,"auth_signals":auth_signals_from_deps(deps),"components":security_components_from_file_list([r["path"] for r in records]),"source_records":records,"diagnostics":diagnostics,"identity_inputs":semantic.get("identity_inputs",[]),"resource_relationships":semantic.get("resource_relationships",[]),"seed_entities":semantic.get("seed_entities",[])}

def inspect_frontend_source(sandbox, adapter, inspection=None):
    if inspection and inspection.get("source_records") is not None: records=inspection["source_records"]; diagnostics=inspection.get("diagnostics",{})
    else: records,diagnostics=walk_repository_source(sandbox,adapter)
    lines=_source_records_to_lines(records); route_lines=[line for line in lines if _FRONTEND_ROUTE_DEF_RE.search(line[2])]
    refs=extract_api_references_from_lines(lines); data,storage,sdk_sources,auth=extract_supabase_resources(records); envs=extract_environment_references_from_lines(lines); browser_storage=extract_storage_signals_from_lines(lines); capabilities=extract_capabilities(records,data,storage); query_params=extract_query_parameters_from_lines(lines); service_types=["supabase"] if sdk_sources else []
    return {"frontend_routes":extract_frontend_routes_from_lines(route_lines),"api_references":refs,"environment_references":envs,"storage_signals":browser_storage,"components":security_components_from_file_list([r["path"] for r in records]),"external_services":sorted(set(extract_external_services(refs))|set(service_types)),"external_service_sdks":[{"type":s,"source":", ".join(sdk_sources)} for s in service_types],"data_resources":data,"storage_resources":storage,"auth_usage":auth,"capabilities":capabilities,"query_params":query_params,"diagnostics":{**diagnostics,"framework_signals":[],"api_candidates":len(refs),"supabase_candidates":len(data)+len(storage)+len(sdk_sources),"storage_candidates":len(browser_storage)+len(storage),"env_references":len(envs)}}

def _response_fingerprint(status,headers,body):
    ctype=next((str(v).split(";",1)[0].lower() for k,v in (headers or {}).items() if k.lower()=="content-type"),"")
    if isinstance(body,str): text=body[:800]; kind="html" if "<html" in text.lower() or "<!doctype" in text.lower() else "text"
    else: text=json.dumps(body,sort_keys=True)[:800]; kind="json"
    return status,ctype,kind,text

def _probe_with_headers(sandbox,client_path,origin,path):
    out=exec_in_sandbox(sandbox,f"python {client_path} --headers GET {shlex.quote(path)}",timeout=60,env={"BREAKTRACE_TARGET_ORIGIN":origin})
    try: value=json.loads(out)
    except (ValueError,TypeError) as exc: raise RuntimeError(f"Malformed header probe output: {out or '(empty)'}") from exc
    return value if isinstance(value,dict) else {}

def build_probe_candidates(inspection):
    candidates=[]; seen=set()
    for method,path in inspection.get("routes",[]):
        if method=="GET" and path not in seen: seen.add(path); candidates.append(path)
    for model in inspection.get("models",[]):
        if model and model!="*":
            path=f"/api/{model}"
            if path not in seen: seen.add(path); candidates.append(path)
    if "/" not in seen: candidates.insert(0,"/")
    return candidates[:40]

def probe_runtime(sandbox,adapter,origin,candidate_paths):
    client_path=f"{adapter.repo_dir}/probe_client.py"; sandbox.fs.upload_file(TARGET_TEST_CLIENT_SOURCE.encode(),client_path)
    root=_probe_with_headers(sandbox,client_path,origin,"/"); random_path=f"/breaktrace-probe-{uuid.uuid4().hex[:12]}"; fallback=_probe_with_headers(sandbox,client_path,origin,random_path)
    root_fp=_response_fingerprint(int(root.get("status",-1)),root.get("headers",{}),root.get("body")); fallback_fp=_response_fingerprint(int(fallback.get("status",-1)),fallback.get("headers",{}),fallback.get("body")); spa=root_fp==fallback_fp and root_fp[0]==200 and root_fp[2]=="html"
    probed=[]; filtered=0
    for i in range(0,len(candidate_paths),25):
        chunk=candidate_paths[i:i+25]; out=exec_in_sandbox(sandbox,f"python {client_path} --probe {shlex.quote('|'.join(chunk))}",timeout=180,env={"BREAKTRACE_TARGET_ORIGIN":origin})
        try: items=json.loads(out)
        except (ValueError,TypeError) as exc: raise RuntimeError(f"Malformed probe output: {out or '(empty)'}") from exc
        for item in items:
            status=int(item["status"]); path=item.get("path","")
            if status==-1: continue
            if spa and path!="/":
                candidate=_probe_with_headers(sandbox,client_path,origin,path); fp=_response_fingerprint(int(candidate.get("status",-1)),candidate.get("headers",{}),candidate.get("body"))
                if fp==fallback_fp: filtered+=1; continue
            probed.append(DiscoveredRoute(method="GET",path=path,source="runtime"))
    return probed,{"spa_fallback_detected":spa,"spa_fallback_probe_path":random_path,"runtime_candidates":len(candidate_paths),"runtime_fallback_responses_filtered":filtered}

def build_application_context(target_id,adapter,inspection,probed_routes,origin,frontend_inspection=None,runtime_diagnostics=None):
    sources={}
    for method,path in inspection.get("routes",[]): sources[(method.upper(),path)]="repository"
    for route in probed_routes:
        key=(route.method.upper(),route.path); sources[key]="both" if key in sources else "runtime"
    frontend=frontend_inspection or {}
    routes=[DiscoveredRoute(method=m,path=p,source=s) for (m,p),s in sorted(sources.items())]
    runtime_routes=[r for r in routes if r.source in ("runtime","both")]
    api_refs=[APIReference(url=r["url"],kind=r["kind"],source="repository") for r in frontend.get("api_references",[])]
    browser_storage=[StorageSignal(storage_type=s["storage_type"],key=s["key"],source="repository") for s in frontend.get("storage_signals",[])]
    components=sorted(set(inspection.get("components",[]))|set(frontend.get("components",[]))); frameworks=inspection.get("frameworks",[]); deps=sorted(inspection.get("deps",{}))
    data=[DataResource(**{**r,"provenance":"repository","confidence":"high"}) for r in frontend.get("data_resources",[])]; storage=[StorageResource(**{**r,"provenance":"repository","confidence":"high"}) for r in frontend.get("storage_resources",[])]; services=[ExternalService(**{**r,"provenance":"repository","confidence":"high"}) for r in frontend.get("external_service_sdks",[])]; caps=[ApplicationCapability(**{**r,"provenance":"repository","confidence":"medium"}) for r in frontend.get("capabilities",[])]
    auth_provider=["Supabase SDK present"] if "@supabase/supabase-js" in inspection.get("deps",{}) else []; auth_usage=frontend.get("auth_usage",[])
    if not auth_usage and auth_provider: auth_usage=["No Supabase auth usage detected in scanned source"]
    query_params=sorted({p["name"] for p in frontend.get("query_params",[])})
    allowed_headers=list(getattr(adapter, "allowed_request_headers", []) or [])
    identity_inputs=[IdentityInput(**d) for d in inspection.get("identity_inputs",[])]
    resource_relationships=[ResourceOwnership(**d) for d in inspection.get("resource_relationships",[])]
    seed_entities=[SeedEntity(**d) for d in inspection.get("seed_entities",[])]
    diagnostics={**inspection.get("diagnostics",{}),**frontend.get("diagnostics",{}),**(runtime_diagnostics or {}),"framework_signals":frameworks,"api_candidates":len(api_refs),"supabase_candidates":len(data)+len(storage),"storage_candidates":len(browser_storage)+len(storage),"env_references":len(frontend.get("environment_references",[])),"identity_inputs":len(identity_inputs),"resource_relationships":len(resource_relationships),"seed_entities":len(seed_entities)}
    summary=f"Discovered {len(routes)} endpoints ({len(runtime_routes)} confirmed at runtime against the sandbox-local instance), framework {inspection.get('framework') or 'unknown'}, {len(inspection.get('models',[]))} models."
    return ApplicationContext(target_id=target_id,name=adapter.name,framework=inspection.get("framework",""),runtime_origin=origin,routes=routes,auth_signals=inspection.get("auth_signals",[]),models=[m for m in inspection.get("models",[]) if m!="*"],security_relevant_components=components,discovery_summary=summary,frontend_routes=[FrontendRoute(path=p,source="repository") for p in frontend.get("frontend_routes",[])],api_references=api_refs,storage_signals=browser_storage,environment_references=frontend.get("environment_references",[]),external_services=frontend.get("external_services",[]),frameworks=frameworks,dependencies=deps,capabilities=caps,external_service_sdks=services,data_resources=data,storage_resources=storage,authentication_provider=auth_provider,authentication_usage=auth_usage,runtime_routes=runtime_routes,spa_fallback_detected=bool((runtime_diagnostics or {}).get("spa_fallback_detected")),query_parameters=query_params,allowed_request_headers=allowed_headers,identity_inputs=identity_inputs,resource_relationships=resource_relationships,seed_entities=seed_entities,discovery_diagnostics=diagnostics)
