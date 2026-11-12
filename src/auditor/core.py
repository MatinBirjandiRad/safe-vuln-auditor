"""Bounded allowlist-driven inventory; OT/IIoT are passive-only."""
from __future__ import annotations
import csv, ipaddress, json, os, socket, ssl, time, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUTH_PHRASE = "I_AUTHORIZE_LOW_IMPACT_AUDIT"
PROBES = ("tcp_connect", "ssh_banner", "http_head", "tls_metadata")
DEFAULT_PORTS = {"tcp_connect": 443, "ssh_banner": 22, "http_head": 80, "tls_metadata": 443}
RISK_CLASSES = {"IT", "IoT", "OT", "IIoT"}
MAX_HOSTS_CIDR, MAX_HOSTS_TOTAL, MAX_ATTEMPTS = 64, 256, 1024

class AuditError(ValueError):
    """Invalid or unsafe scope/configuration."""

def validate_ip(value: Any) -> str:
    if not isinstance(value, str) or not value or "/" in value or "%" in value:
        raise AuditError("Target must be an IPv4/IPv6 literal (no CIDR or zone ID)")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AuditError("Target must be an IPv4/IPv6 literal; DNS names are not accepted") from exc
    docs = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32"))
    if (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved
            or addr.is_link_local or any(addr.version == n.version and addr in n for n in docs)):
        raise AuditError(f"Disallowed special-use IP: {value}")
    return str(addr)

def check_authorization(scope: dict[str, Any]) -> None:
    if not isinstance(scope, dict):
        raise AuditError("Configuration must be a JSON object")
    if scope.get("approval") is not True:
        raise AuditError("approval must be true")
    if scope.get("explicit_authorization_phrase") != AUTH_PHRASE:
        raise AuditError("explicit_authorization_phrase does not match")
    allowed = scope.get("allowed_risk_classes", ["IT"])
    if (not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) or x not in RISK_CLASSES for x in allowed)
            or len(set(allowed)) != len(allowed) or "IT" not in allowed):
        raise AuditError("allowed_risk_classes must include IT and contain supported unique labels")

def _valid_port(port: Any) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535

def _network_item(item: Any):
    if not isinstance(item, dict):
        raise AuditError("Each CIDR entry must be an object")
    risk = item.get("risk_class")
    if risk not in RISK_CLASSES:
        raise AuditError("CIDR risk_class must be IT, IoT, OT, or IIoT")
    try:
        net = ipaddress.ip_network(item.get("cidr"), strict=True)
    except (ValueError, TypeError) as exc:
        raise AuditError("CIDR must be a canonical IPv4/IPv6 network (strict=true)") from exc
    if net.num_addresses > MAX_HOSTS_CIDR:
        raise AuditError("Each CIDR may contain at most 64 addresses")
    hosts = list(net.hosts())
    if not hosts:
        raise AuditError("CIDR has no usable hosts")
    for addr in hosts:
        validate_ip(str(addr))
    ports = item.get("ports")
    if not isinstance(ports, list) or not ports or len(ports) > 16 or any(not _valid_port(p) for p in ports):
        raise AuditError("Each CIDR requires 1-16 explicit valid TCP ports")
    ports = list(dict.fromkeys(ports))
    if risk == "IoT" and any(p not in {22, 80, 443, 8080, 8443} for p in ports):
        raise AuditError("IoT active inventory is limited to ports 22, 80, 443, 8080, 8443")
    return net, risk, ports

def validate_scope(scope: dict[str, Any]) -> dict[str, Any]:
    check_authorization(scope)
    max_ports = scope.get("max_ports_per_target", 16)
    if isinstance(max_ports, bool) or not isinstance(max_ports, int) or not 1 <= max_ports <= 16:
        raise AuditError("max_ports_per_target must be an integer from 1 to 16")
    approved = set(scope.get("allowed_risk_classes", ["IT"]))
    cidrs = scope.get("cidrs", [])
    if not isinstance(cidrs, list):
        raise AuditError("cidrs must be a list")
    networks, total_hosts, attempts = [], 0, 0
    for item in cidrs:
        net, risk, ports = _network_item(item)
        if risk not in approved:
            raise AuditError(f"Risk class {risk} is not in allowed_risk_classes")
        if any(net.version == old.version and net.overlaps(old) for old, *_ in networks):
            raise AuditError("Overlapping or duplicate CIDR segments are not allowed")
        hosts = list(net.hosts())
        total_hosts += len(hosts)
        if total_hosts > MAX_HOSTS_TOTAL:
            raise AuditError("Total expanded hosts may not exceed 256")
        if risk in ("IT", "IoT"):
            attempts += len(hosts) * len(ports)
        networks.append((net, risk, ports, hosts))
    delay, timeout = scope.get("min_delay_seconds", 1.0), scope.get("socket_timeout_seconds", 1.5)
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 1:
        raise AuditError("min_delay_seconds must be at least 1.0")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 1.5:
        raise AuditError("socket_timeout_seconds must be >0 and <=1.5")
    if attempts > MAX_ATTEMPTS:
        raise AuditError("Total TCP attempts may not exceed 1024")
    if any(r == "IoT" for _, r, _, _ in networks) and scope.get("iot_active_approved") is not True:
        raise AuditError("IoT CIDRs require iot_active_approved=true")
    targets = scope.get("targets", [])
    if not isinstance(targets, list):
        raise AuditError("targets must be a list")
    clean = []
    for item in targets:
        if isinstance(item, str):
            clean.append({"ip": validate_ip(item), "risk_class": "IT"})
        elif isinstance(item, dict):
            if item.get("risk_class", "IT") != "IT" or "IT" not in approved:
                raise AuditError("Legacy explicit targets support authorized IT only")
            clean.append({"ip": validate_ip(item.get("ip")), "risk_class": "IT"})
        else:
            raise AuditError("Each target must be an IP literal or target object")
    if len({x["ip"] for x in clean}) != len(clean):
        raise AuditError("Duplicate explicit targets are not allowed")
    endpoints = scope.get("endpoints", [])
    if not isinstance(endpoints, list):
        raise AuditError("endpoints must be a list")
    normalized, seen = [], set()
    for e in endpoints:
        if not isinstance(e, dict) or e.get("probe") not in PROBES:
            raise AuditError("Endpoint probe must be one of the supported probes")
        ip = validate_ip(e.get("ip"))
        port = e.get("port", DEFAULT_PORTS[e["probe"]])
        if not _valid_port(port):
            raise AuditError("Invalid endpoint port")
        if ip not in {x["ip"] for x in clean}:
            raise AuditError("Legacy endpoint IP must be an explicitly scoped target")
        if (ip, port) in seen:
            raise AuditError("Duplicate explicit endpoint")
        seen.add((ip, port))
        normalized.append({"ip": ip, "port": port, "probe": e["probe"]})
    if len(normalized) > max_ports * max(1, len(clean)):
        raise AuditError("Endpoint count exceeds max_ports_per_target")
    attempts += len(normalized)
    if attempts > MAX_ATTEMPTS:
        raise AuditError("Total TCP attempts may not exceed 1024")
    for t in clean:
        addr = ipaddress.ip_address(t["ip"])
        if any(r in ("OT", "IIoT") and addr.version == net.version and addr in net for net, r, *_ in networks):
            raise AuditError("Legacy active target overlaps OT/IIoT scope")
    return {**scope, "targets": clean, "endpoints": normalized, "cidrs": cidrs,
            "_networks": networks, "_attempts": attempts, "min_delay_seconds": float(delay),
            "socket_timeout_seconds": float(timeout)}

def candidate_endpoints(scope):
    return [dict(e) for e in scope.get("endpoints", [])]

def _connect(ip, port, timeout=1.5):
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def run_probe(endpoint, timeout=1.5):
    ip, port, kind = endpoint["ip"], endpoint["port"], endpoint["probe"]
    result = {"ip": ip, "port": port, "probe": kind, "status": "unknown"}
    try:
        if kind == "tcp_connect":
            with _connect(ip, port, timeout): pass
            result.update(status="open", detail="TCP connection accepted")
        elif kind == "ssh_banner":
            with _connect(ip, port, timeout) as sock: data = sock.recv(256)
            result.update(status="open", detail=data.decode("ascii", "replace").strip()[:200])
        elif kind == "http_head":
            host = f"[{ip}]" if ":" in ip else ip
            req = urllib.request.Request(f"http://{host}:{port}/", method="HEAD", headers={"User-Agent": "safe-vuln-auditor/1.0"})
            opener = urllib.request.build_opener(_NoRedirect())
            try:
                with opener.open(req, timeout=timeout) as resp:
                    result.update(status="responded", detail={"status_code": resp.status, "server": resp.headers.get("Server", "")[:200]})
            except urllib.error.HTTPError as exc:
                result.update(status="responded", detail={"status_code": exc.code, "server": exc.headers.get("Server", "")[:200]})
        elif kind == "tls_metadata":
            with _connect(ip, port, timeout) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=None) as tls:
                    cert = tls.getpeercert() or {}
                    result.update(status="responded", detail={"tls_version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None,
                                 "certificate_subject": str(cert.get("subject", []))[:300], "not_after": cert.get("notAfter")})
        else: raise AuditError("Unsupported probe")
    except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
        result.update(status="error", detail=type(exc).__name__)
    return result

def _advisory_fallback(reason="LLM analysis unavailable"):
    return {"status": "unavailable", "advisory": True, "evidence_grounded": True,
            "vulnerability_analysis": "No AI assessment was produced. Observations are inventory evidence only and do not confirm a vulnerability.",
            "risk_rating": "Unrated (advisory)", "remediation_recommendations": [
                "Review observed exposure and service configuration with the responsible system owner.",
                "Apply vendor-supported updates only through approved change management and compatibility testing.",
                "Restrict access to required trusted sources and monitor logs; avoid unplanned changes."], "note": reason}

def llm_select_candidates(candidates, **kwargs):
    return candidates

def llm_analyze_findings(results, *, base_url=None, model=None, api_key=None, timeout=15.0):
    base = (base_url if base_url is not None else os.getenv("LLM_BASE_URL", "")).strip().rstrip("/")
    selected = model if model is not None else os.getenv("LLM_MODEL", "")
    key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
    if not base or not selected:
        return _advisory_fallback("LLM_BASE_URL or LLM_MODEL is not configured")
    safe = []
    for x in results[:256]:
        safe.append({"ip": str(x.get("ip", ""))[:64], "port": x.get("port") if _valid_port(x.get("port")) else None,
                     "probe": str(x.get("probe", ""))[:32], "status": str(x.get("status", ""))[:32],
                     "risk_class": str(x.get("risk_class", ""))[:8], "detail": str(x.get("detail", ""))[:300]})
    prompt = ("Interpret only these bounded authorized probe observations. Port presence alone is not a vulnerability. "
              "Do not infer CVEs, vendors, firmware, or facts not observed. For OT/IIoT describe only possible exposure "
              "and safe change-control remediation; advisory only. Return JSON keys vulnerability_analysis, risk_rating, "
              "remediation_recommendations. Observations: " + json.dumps(safe, ensure_ascii=False))
    body = json.dumps({"model": selected, "temperature": 0, "messages": [{"role": "user", "content": prompt}],
                       "response_format": {"type": "json_object"}}).encode()
    headers = {"Content-Type": "application/json"}
    if key: headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(base + "/v1/chat/completions", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read(1_000_000))
        d = json.loads(payload["choices"][0]["message"]["content"])
        a, r, rec = d.get("vulnerability_analysis"), d.get("risk_rating"), d.get("remediation_recommendations")
        if not isinstance(a, str) or not isinstance(r, str) or not isinstance(rec, list) or not all(isinstance(x, str) for x in rec):
            raise ValueError("Invalid response schema")
        return {"status": "available", "advisory": True, "evidence_grounded": True,
                "vulnerability_analysis": a[:4000], "risk_rating": r[:200],
                "remediation_recommendations": [x[:1000] for x in rec[:20]],
                "note": "Advisory only; no vulnerability or CVE is confirmed."}
    except Exception:
        return _advisory_fallback("LLM request failed or returned invalid JSON")

def _passive_inventory(scope, config_path=None):
    required = any(r in ("OT", "IIoT") for _, r, _, _ in scope["_networks"])
    name = scope.get("passive_inventory_file")
    if required and not name:
        raise AuditError("OT/IIoT CIDRs require passive_inventory_file; no active OT/IIoT traffic is performed")
    if not name: return []
    if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
        raise AuditError("passive_inventory_file must be a safe relative path")
    root = Path(config_path).resolve().parent if config_path else Path.cwd().resolve()
    candidate = root / name
    if candidate.is_symlink(): raise AuditError("Passive inventory symlinks are not accepted")
    try:
        path = candidate.resolve(strict=True); path.relative_to(root)
    except (OSError, ValueError) as exc:
        raise AuditError("Passive inventory must exist under the config directory") from exc
    if path.stat().st_size > 1_000_000: raise AuditError("Passive inventory CSV exceeds 1 MB")
    allowed = [(n, r, set(p)) for n, r, p, _ in scope["_networks"] if r in ("OT", "IIoT")]
    observed, seen = [], set()
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or not {"ip", "port"}.issubset(reader.fieldnames):
                raise AuditError("Passive CSV requires ip,port headers")
            for idx, row in enumerate(reader, 1):
                if idx > 1024: raise AuditError("Passive CSV may contain at most 1024 records")
                try:
                    ip = validate_ip((row.get("ip") or "").strip()); port = int((row.get("port") or "").strip())
                except (AuditError, ValueError) as exc:
                    raise AuditError(f"Malformed passive inventory row {idx}") from exc
                if not _valid_port(port): raise AuditError(f"Invalid passive inventory port at row {idx}")
                addr = ipaddress.ip_address(ip)
                match = next(((n, r, p) for n, r, p in allowed if addr.version == n.version and addr in n), None)
                if not match: raise AuditError(f"Passive inventory row {idx} is outside explicitly approved OT/IIoT CIDRs")
                net, risk, ports = match
                if port not in ports: raise AuditError(f"Passive inventory row {idx} port is not listed in its approved CIDR")
                key = (ip, port)
                if key in seen: continue
                seen.add(key)
                observed.append({"ip": ip, "port": port, "risk_class": risk, "status": "observed_passive",
                                 "evidence_provenance": "user-provided passive inventory CSV",
                                 "source": str(row.get("source", "") or "")[:100],
                                 "observed_at": str(row.get("observed_at", "") or "")[:100],
                                 "detail": "Passive record only; service liveness and vulnerability are not verified."})
    except UnicodeError as exc:
        raise AuditError("Passive inventory must be valid UTF-8 CSV") from exc
    return observed

def _discovery(scope, dry_run=False):
    inventory = _passive_inventory(scope, scope.get("_config_path"))
    found = {(x["ip"], x["port"]): x for x in inventory}
    results, delay, timeout, last = [], scope["min_delay_seconds"], scope["socket_timeout_seconds"], None
    for net, risk, ports, hosts in scope["_networks"]:
        for address in hosts:
            ip, port_results = str(address), []
            for port in ports:
                if risk in ("OT", "IIoT"):
                    record = found.get((ip, port))
                    status = "observed_passive" if record else "unknown_not_in_passive_inventory"
                    port_results.append({"port": port, "status": status,
                        "evidence_provenance": "user-provided passive inventory CSV" if record else "no passive record",
                        "detail": "No OT/IIoT network traffic is sent; absence from inventory does not mean safe or absent."})
                elif dry_run:
                    port_results.append({"port": port, "status": "candidate", "evidence_provenance": "approved CIDR/port configuration", "detail": "dry-run: no network access"})
                else:
                    if risk == "IoT" and scope.get("iot_active_approved") is not True: raise AuditError("IoT active approval missing")
                    if last is not None: time.sleep(max(delay, 1.0))
                    last = time.monotonic()
                    try:
                        with _connect(ip, port, timeout): pass
                        status, detail = "open_observed", "One TCP connect accepted; no application data sent."
                    except (OSError, TimeoutError) as exc:
                        status, detail = "closed_or_filtered_unknown", type(exc).__name__
                    port_results.append({"port": port, "status": status,
                        "evidence_provenance": "single bounded TCP connect" if status == "open_observed" else "TCP connect attempt; closed/filtered/timeout indistinguishable", "detail": detail})
            if risk in ("OT", "IIoT"):
                host_status = "passive_observed" if any(x["status"] == "observed_passive" for x in port_results) else "not_in_passive_inventory_unknown"
            elif dry_run: host_status = "candidate"
            elif any(x["status"] == "open_observed" for x in port_results): host_status = "responded_on_selected_tcp_port"
            else: host_status = "host_silent_not_necessarily_absent"
            results.append({"ip": ip, "risk_class": risk, "status": host_status, "ports": port_results,
                            "evidence_provenance": "explicit approved CIDR and user-selected ports",
                            "active_tcp_attempts": len(ports) if risk in ("IT", "IoT") and not dry_run else 0,
                            "note": "Port observations alone do not establish a vulnerability; silence does not establish absence."})
    return results

def make_report(results, dry_run=False, ai_analysis=None, discovery=None):
    advisory = ai_analysis or _advisory_fallback(); discovery = discovery or []
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "dry_run": dry_run, "results": results,
              "discovery": discovery, "ai_analysis": advisory,
              "ai_vulnerability_analysis_advisory_findings": advisory.get("vulnerability_analysis", ""),
              "non_disruptive_remediation_recommendations": advisory.get("remediation_recommendations", [])}
    lines = ["# Safe Vulnerability Auditor report", "", f"- Generated: {report['generated_at']}", f"- Dry run: {dry_run}", "",
             "## Discovery by IP and selected port", "", "| IP | Class | Host status | Ports / evidence |", "|---|---|---|---|"]
    for host in discovery:
        ports = "; ".join(f"{x['port']}: {x['status']} ({x['evidence_provenance']})" for x in host["ports"])
        lines.append(f"| {host['ip']} | {host['risk_class']} | {host['status']} | {ports} |")
    lines += ["", "Silence is not proof of absence. Open ports are observations, not vulnerabilities. OT/IIoT receive no active network traffic.",
              "", "## Explicit legacy probe observations", "", "| IP | Port | Probe | Status | Detail |", "|---|---:|---|---|---|"]
    for x in results:
        detail = json.dumps(x.get("detail", ""), ensure_ascii=False).replace("|", "\\|")
        lines.append(f"| {x.get('ip','')} | {x.get('port','')} | {x.get('probe','')} | {x.get('status','')} | {detail} |")
    lines += ["", "## AI vulnerability analysis and advisory findings", "", "**Advisory only; observed ports do not confirm vulnerabilities or CVEs.**", "",
              str(advisory.get("vulnerability_analysis", "No analysis available.")), "", f"**Risk:** {advisory.get('risk_rating','Unrated (advisory)')}",
              "", "## Non-disruptive remediation recommendations", ""]
    lines += [f"{i}. {text}" for i, text in enumerate(advisory.get("remediation_recommendations", []), 1)] or ["No recommendations available."]
    lines += ["", f"_AI status: {advisory.get('status','unknown')}; {advisory.get('note','')}_"]
    return report, "\n".join(lines) + "\n"

def audit(scope, output_dir="/output", dry_run=False, config_path=None):
    scope = validate_scope(scope); scope["_config_path"] = str(config_path) if config_path else None
    # Validate passive records and all scopes before any active connection.
    _passive_inventory(scope, config_path)
    discovery = _discovery(scope, dry_run)
    legacy = []
    for endpoint in scope["endpoints"]:
        if dry_run: legacy.append({**endpoint, "status": "candidate", "detail": "dry-run: network access bypassed"})
        else: legacy.append(run_probe(endpoint, scope["socket_timeout_seconds"]))
    observations = []
    for host in discovery:
        for item in host["ports"]:
            if item["status"] in ("open_observed", "observed_passive"):
                observations.append({"ip": host["ip"], "port": item["port"], "probe": "tcp_connect" if item["status"] == "open_observed" else "passive_inventory",
                                    "status": item["status"], "detail": item["detail"], "risk_class": host["risk_class"]})
    if dry_run: analysis = _advisory_fallback("dry-run: no network or LLM access")
    else: analysis = llm_analyze_findings((observations + legacy)[:256])
    report, md = make_report(legacy, dry_run, analysis, discovery)
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(md, encoding="utf-8")
    return legacy
