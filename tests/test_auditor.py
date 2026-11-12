import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.auditor.core import (
    AUTH_PHRASE, AuditError, audit, check_authorization, llm_analyze_findings,
    validate_ip, validate_scope,
)

def scope_base(**extra):
    data = {"approval": True, "explicit_authorization_phrase": AUTH_PHRASE,
            "allowed_risk_classes": ["IT"], "targets": [], "endpoints": [],
            "max_ports_per_target": 16, "cidrs": []}
    data.update(extra)
    return data

class AuditorTests(unittest.TestCase):
    def test_ip_literal_allow_and_deny(self):
        self.assertEqual(validate_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(validate_ip("2001:4860:4860::8888"), "2001:4860:4860::8888")
        for bad in ["localhost", "10.0.0.1/24", "127.0.0.1", "::1", "224.0.0.1",
                    "0.0.0.0", "169.254.1.1", "fe80::1", "192.0.2.1", "8.8.8.8%eth0"]:
            with self.subTest(bad=bad), self.assertRaises(AuditError): validate_ip(bad)

    def test_authorization_validation(self):
        good = scope_base()
        check_authorization(good)
        for patch_values in [{"approval": False}, {"explicit_authorization_phrase": "wrong"},
                             {"allowed_risk_classes": ["OT"]}, {"allowed_risk_classes": ["IT", "bogus"]}]:
            with self.subTest(patch_values=patch_values), self.assertRaises(AuditError):
                check_authorization({**good, **patch_values})
        with self.assertRaises(AuditError): check_authorization([])

    def test_authorized_risk_classes_must_include_it(self):
        check_authorization(scope_base(allowed_risk_classes=["IT", "OT", "IoT", "IIoT"]))
        with self.assertRaises(AuditError): check_authorization(scope_base(allowed_risk_classes=["OT"]))

    def test_cidr_expansion_hosts_and_ports(self):
        validated = validate_scope(scope_base(allowed_risk_classes=["IT"], cidrs=[
            {"cidr": "8.8.8.0/30", "risk_class": "IT", "ports": [80, 443]}]))
        self.assertEqual([str(ip) for ip in validated["_networks"][0][3]], ["8.8.8.1", "8.8.8.2"])
        self.assertEqual(validated["_attempts"], 4)

    def test_cidr_limits_overlap_and_network_canonicalization(self):
        for entries in [
            [{"cidr": "8.8.8.0/24", "risk_class": "IT", "ports": [80]}],
            [{"cidr": "8.8.8.0/30", "risk_class": "IT", "ports": [80]},
             {"cidr": "8.8.8.0/31", "risk_class": "IT", "ports": [80]}],
            [{"cidr": "8.8.8.1/30", "risk_class": "IT", "ports": [80]}],
        ]:
            with self.subTest(entries=entries), self.assertRaises(AuditError):
                validate_scope(scope_base(cidrs=entries))

    def test_scope_rejects_invalid_ports_and_limits(self):
        for ports in [[], [0], [65536], [True], list(range(1, 18))]:
            with self.subTest(ports=ports), self.assertRaises(AuditError):
                validate_scope(scope_base(cidrs=[{"cidr": "8.8.8.0/30", "risk_class": "IT", "ports": ports}]))
        with self.assertRaises(AuditError): validate_scope(scope_base(max_ports_per_target=17))
        with self.assertRaises(AuditError): validate_scope(scope_base(min_delay_seconds=0.5))

    def test_iot_requires_approval_and_port_allowlist(self):
        item = {"cidr": "8.8.8.0/30", "risk_class": "IoT", "ports": [80]}
        with self.assertRaises(AuditError): validate_scope(scope_base(allowed_risk_classes=["IT", "IoT"], cidrs=[item]))
        valid = validate_scope(scope_base(allowed_risk_classes=["IT", "IoT"], cidrs=[item], iot_active_approved=True))
        self.assertEqual(valid["_networks"][0][1], "IoT")
        with self.assertRaises(AuditError):
            validate_scope(scope_base(allowed_risk_classes=["IT", "IoT"], cidrs=[{**item, "ports": [502]}], iot_active_approved=True))

    def test_ot_is_passive_only_and_requires_inventory(self):
        scope = scope_base(allowed_risk_classes=["IT", "OT"], cidrs=[
            {"cidr": "8.8.8.0/30", "risk_class": "OT", "ports": [502]}])
        with self.assertRaises(AuditError): audit(scope, tempfile.mkdtemp(), dry_run=True)

    def test_ot_passive_csv_report_and_no_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "ot.csv").write_text("ip,port,source,observed_at\n8.8.8.1,502,asset-register,2025-01-01\n", encoding="utf-8")
            scope = scope_base(allowed_risk_classes=["IT", "OT"], passive_inventory_file="ot.csv", cidrs=[
                {"cidr": "8.8.8.0/30", "risk_class": "OT", "ports": [502]}])
            with patch("src.auditor.core._connect", side_effect=AssertionError("OT must not connect")):
                audit(scope, root / "out", dry_run=False, config_path=root / "scope.json")
            report = json.loads((root / "out/report.json").read_text())
            self.assertEqual(report["discovery"][0]["ports"][0]["status"], "observed_passive")
            self.assertEqual(report["discovery"][1]["ports"][0]["status"], "unknown_not_in_passive_inventory")
            self.assertIn("no active network traffic", (root / "out/report.md").read_text())

    def test_dry_run_dynamic_discovery_has_no_network_or_llm(self):
        scope = scope_base(cidrs=[{"cidr": "8.8.8.0/30", "risk_class": "IT", "ports": [80, 443]}])
        with tempfile.TemporaryDirectory() as tmp, patch("src.auditor.core._connect", side_effect=AssertionError), \
             patch("src.auditor.core.llm_analyze_findings") as ai:
            legacy = audit(scope, tmp, dry_run=True)
            ai.assert_not_called()
            report = json.loads((Path(tmp) / "report.json").read_text())
            self.assertEqual(legacy, [])
            self.assertEqual(len(report["discovery"]), 2)
            self.assertEqual([p["status"] for p in report["discovery"][0]["ports"]], ["candidate", "candidate"])

    def test_llm_analysis_success_and_bounded_prompt(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit):
                return json.dumps({"choices": [{"message": {"content": json.dumps({
                    "vulnerability_analysis": "An SSH service responded; no flaw proven.",
                    "risk_rating": "Low (advisory)", "remediation_recommendations": ["Review service configuration."]})}}]}).encode()
        with patch("src.auditor.core.urllib.request.urlopen", return_value=Response()) as request:
            result = llm_analyze_findings([{"ip": "8.8.8.8", "port": 22, "probe": "ssh_banner", "status": "open", "detail": "SSH-2.0"}],
                base_url="http://localhost:11434", model="test-model", api_key="", timeout=1)
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["advisory"])
        body = json.loads(request.call_args.args[0].data)
        self.assertEqual(body["temperature"], 0)
        self.assertIn("probe observations", body["messages"][0]["content"])

    def test_llm_api_failure_or_bad_schema_falls_back(self):
        with patch("src.auditor.core.urllib.request.urlopen", side_effect=OSError("offline")):
            result = llm_analyze_findings([], base_url="http://localhost:11434", model="test", api_key="")
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(result["remediation_recommendations"])
        self.assertEqual(llm_analyze_findings([], base_url="", model="")["status"], "unavailable")
        class BadResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return b'{"choices":[]}'
        with patch("src.auditor.core.urllib.request.urlopen", return_value=BadResponse()):
            self.assertEqual(llm_analyze_findings([], base_url="http://localhost", model="x")["status"], "unavailable")

    def test_explicit_probe_audit_preserves_compatibility(self):
        scope = scope_base(targets=["8.8.8.8"], endpoints=[{"ip": "8.8.8.8", "port": 443, "probe": "tcp_connect"}])
        result = {"ip": "8.8.8.8", "port": 443, "probe": "tcp_connect", "status": "open", "detail": "TCP accepted"}
        ai = {"status": "available", "advisory": True, "evidence_grounded": True,
              "vulnerability_analysis": "No flaw confirmed", "risk_rating": "Unrated (advisory)",
              "remediation_recommendations": ["Review configuration"]}
        with tempfile.TemporaryDirectory() as tmp, patch("src.auditor.core.run_probe", return_value=result) as probe, \
             patch("src.auditor.core.llm_analyze_findings", return_value=ai) as analyze:
            self.assertEqual(audit(scope, tmp), [result])
            probe.assert_called_once_with(scope["endpoints"][0], 1.5)
            analyze.assert_called_once_with([result])
            report = json.loads((Path(tmp) / "report.json").read_text())
            self.assertEqual(report["ai_analysis"], ai)

    def test_passive_csv_path_traversal_rejected(self):
        scope = scope_base(allowed_risk_classes=["IT", "OT"], passive_inventory_file="../outside.csv", cidrs=[
            {"cidr": "8.8.8.0/30", "risk_class": "OT", "ports": [502]}])
        with self.assertRaises(AuditError): audit(scope, tempfile.mkdtemp(), dry_run=True)

if __name__ == "__main__": unittest.main()
