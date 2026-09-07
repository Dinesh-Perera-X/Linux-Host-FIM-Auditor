from typing import Dict, Any, Optional

class ThreatClassifier:
    """
    Correlates filesystem integrity violations to MITRE ATT&CK tactics,
    techniques, and SOC incident severity ratings.
    """

    SIGNATURES = {
        "/etc/shadow": {
            "technique_id": "T1003.008",
            "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "tactic": "Credential Access",
            "severity": "CRITICAL",
            "soc_action": "Verify shadow hashes immediately; check for rogue administrative accounts."
        },
        "/etc/passwd": {
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "tactic": "Persistence",
            "severity": "CRITICAL",
            "soc_action": "Audit UID 0 accounts; inspect for unauthorized backdoor users."
        },
        "/etc/sudoers": {
            "technique_id": "T1548.003",
            "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudoers",
            "tactic": "Privilege Escalation",
            "severity": "CRITICAL",
            "soc_action": "Review NOPASSWD directives; verify administrative change tickets."
        },
        "/etc/crontab": {
            "technique_id": "T1053.003",
            "technique_name": "Scheduled Task/Job: Cron",
            "tactic": "Persistence",
            "severity": "HIGH",
            "soc_action": "Inspect cron jobs for reverse shells or scheduled payload downloads."
        },
        "/etc/ssh/sshd_config": {
            "technique_id": "T1098.004",
            "technique_name": "Account Manipulation: SSH Authorized Keys",
            "tactic": "Persistence / Defense Evasion",
            "severity": "HIGH",
            "soc_action": "Verify PermitRootLogin and PasswordAuthentication configurations."
        },
        "/etc/hosts": {
            "technique_id": "T1565.001",
            "technique_name": "Data Manipulation: Stored Data Manipulation",
            "tactic": "Impact / Defense Evasion",
            "severity": "MEDIUM",
            "soc_action": "Inspect for DNS redirection or local sinkholing of security endpoints."
        }
    }

    @classmethod
    def classify_event(cls, filepath: str, event_type: str, drift_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Maps an asset drift event to threat intelligence metadata."""
        matched_sig = None

        for sig_path, meta in cls.SIGNATURES.items():
            if filepath.startswith(sig_path):
                matched_sig = meta
                break

        if not matched_sig:
            if "cron" in filepath:
                matched_sig = {
                    "technique_id": "T1053.003",
                    "technique_name": "Scheduled Task/Job: Cron",
                    "tactic": "Persistence",
                    "severity": "HIGH",
                    "soc_action": "Check newly dropped persistence scripts in cron paths."
                }
            elif "sudoers" in filepath:
                matched_sig = {
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudoers",
                    "tactic": "Privilege Escalation",
                    "severity": "CRITICAL",
                    "soc_action": "Review newly dropped sudo drop-in files."
                }
            else:
                matched_sig = {
                    "technique_id": "T1565",
                    "technique_name": "Data Manipulation",
                    "tactic": "Defense Evasion",
                    "severity": "MEDIUM",
                    "soc_action": "Investigate source process responsible for uncataloged filesystem write."
                }

        # Boost severity if permission changed to SUID or world-writable
        if event_type == "PERMISSION_DRIFT" and drift_info:
            current_perms = drift_info.get("current_permissions", "")
            if "777" in current_perms or "4755" in current_perms:
                matched_sig["severity"] = "CRITICAL"
                matched_sig["technique_id"] = "T1548.001"
                matched_sig["technique_name"] = "Setuid and Setgid"
                matched_sig["soc_action"] = "Potential SUID backdoor implant. Revoke permissions immediately."

        return matched_sig
