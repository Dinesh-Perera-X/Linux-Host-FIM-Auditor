import json
import os
from typing import Dict, List, Any
from core.hasher import IntegrityHasher
from core.classifier import ThreatClassifier

class IntegrityScanner:
    """
    Compares the live state of monitored filesystem assets against 
    the baseline cryptographic database to detect unauthorized drifts,
    enriching findings with MITRE ATT&CK threat intelligence.
    """

    def __init__(self, baseline_db_path: str = "baseline.db"):
        self.baseline_db_path = baseline_db_path
        self.baseline = self._load_baseline()

    def _load_baseline(self) -> Dict[str, Any]:
        if not os.path.exists(self.baseline_db_path):
            return {}
        try:
            with open(self.baseline_db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def run_scan(self, targets_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Executes a comparative integrity scan and returns enriched security drifts."""
        findings = []

        for filepath, baseline_meta in self.baseline.items():
            if not os.path.exists(filepath):
                threat_meta = ThreatClassifier.classify_event(filepath, "DELETED")
                findings.append({
                    "filepath": filepath,
                    "event_type": "DELETED",
                    "severity": threat_meta["severity"],
                    "description": "Monitored critical system file has been removed or deleted.",
                    "threat": threat_meta,
                    "drift": {"baseline": baseline_meta, "current": None}
                })
                continue

            current_meta = IntegrityHasher.get_file_metadata(filepath)
            if not current_meta:
                continue

            # Check for SHA-256 content drift
            if baseline_meta.get("sha256") and current_meta.get("sha256") != baseline_meta.get("sha256"):
                threat_meta = ThreatClassifier.classify_event(filepath, "CONTENT_MODIFIED")
                findings.append({
                    "filepath": filepath,
                    "event_type": "CONTENT_MODIFIED",
                    "severity": threat_meta["severity"],
                    "description": "Cryptographic checksum mismatch detected. File content altered.",
                    "threat": threat_meta,
                    "drift": {
                        "baseline_sha256": baseline_meta.get("sha256"),
                        "current_sha256": current_meta.get("sha256")
                    }
                })

            # Check for POSIX permission drift
            if baseline_meta.get("permissions_octal") != current_meta.get("permissions_octal"):
                drift_info = {
                    "baseline_permissions": baseline_meta.get("permissions_octal"),
                    "current_permissions": current_meta.get("permissions_octal")
                }
                threat_meta = ThreatClassifier.classify_event(filepath, "PERMISSION_DRIFT", drift_info)
                findings.append({
                    "filepath": filepath,
                    "event_type": "PERMISSION_DRIFT",
                    "severity": threat_meta["severity"],
                    "description": f"File permission altered from {baseline_meta.get('permissions_octal')} to {current_meta.get('permissions_octal')}.",
                    "threat": threat_meta,
                    "drift": drift_info
                })

        return findings
