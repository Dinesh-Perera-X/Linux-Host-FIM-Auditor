import argparse
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.hasher import IntegrityHasher
from core.scanner import IntegrityScanner

console = Console()

def display_banner():
    banner = (
        "[bold cyan]Linux Host File Integrity Monitor (FIM) & System Auditor 🛡️🐧[/bold cyan]\n"
        "[dim]Host-Based Intrusion Detection & Baseline Tamper Detection Engine[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def load_config(config_path: str = "config/targets.json"):
    if not os.path.exists(config_path):
        return {"monitored_files": ["/etc/passwd", "/etc/hosts", "/etc/group"], "monitored_directories": []}
    with open(config_path, "r") as f:
        return json.load(f)

def generate_baseline(targets, output_db: str = "baseline.db"):
    baseline_records = {}
    console.print("[*] Generating baseline cryptographic state for target system assets...")

    table = Table(title="[bold cyan]🔒 Linux System Asset Baseline Catalog[/bold cyan]", border_style="cyan")
    table.add_column("Target Path", style="white")
    table.add_column("Permissions", justify="center", style="yellow")
    table.add_column("Size", justify="right", style="green")
    table.add_column("SHA-256 Checksum", style="dim cyan")
    table.add_column("Status", justify="center")

    for file_path in targets.get("monitored_files", []):
        meta = IntegrityHasher.get_file_metadata(file_path)
        if meta:
            baseline_records[file_path] = meta
            table.add_row(
                file_path,
                meta["permissions_octal"],
                f"{meta['size_bytes']} B",
                meta["sha256"][:24] + "..." if meta["sha256"] else "[dim]DIRECTORY[/dim]",
                "[bold green]INDEXED[/bold green]"
            )
        else:
            table.add_row(file_path, "-", "-", "-", "[dim yellow]NOT FOUND/DENIED[/dim yellow]")

    with open(output_db, "w", encoding="utf-8") as f:
        json.dump(baseline_records, f, indent=2)

    console.print(table)
    console.print(f"\n[bold green]✔ Baseline Snapshot Stored:[/bold green] [cyan]{output_db}[/cyan] ({len(baseline_records)} assets cataloged)")

def perform_scan(targets, database_path: str = "baseline.db"):
    if not os.path.exists(database_path):
        console.print(f"[red][!] Error: Baseline database '{database_path}' not found. Run with --init first.[/red]")
        sys.exit(1)

    scanner = IntegrityScanner(baseline_db_path=database_path)
    console.print("[*] Running comparative filesystem integrity audit against baseline database...\n")
    findings = scanner.run_scan(targets)

    if not findings:
        console.print(Panel("[bold green]✔ SYSTEM INTEGRITY VERIFIED[/bold green]\nNo unauthorized content drifts, checksum mismatches, or permission modifications detected across monitored assets.", border_style="green"))
    else:
        table = Table(title="[bold red]🚨 File Integrity Violations & Drifts Detected[/bold red]", border_style="red")
        table.add_column("Target Asset", style="white")
        table.add_column("Drift Type", justify="center", style="magenta")
        table.add_column("Severity", justify="center")
        table.add_column("Forensic Anomaly Details", style="yellow")

        for f in findings:
            sev = f["severity"]
            sev_str = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[bold yellow]{sev}[/bold yellow]"
            table.add_row(
                f["filepath"],
                f["event_type"],
                sev_str,
                f["description"]
            )
        console.print(table)

    console.print("\n[bold green]✔ Day 2 Complete:[/bold green] Differential integrity scan and tamper drift engine operational.")

def main():
    parser = argparse.ArgumentParser(description="Linux Host File Integrity Monitor (FIM).")
    parser.add_argument("--init", action="store_true", help="Initialize and generate a fresh cryptographic baseline snapshot")
    parser.add_argument("--scan", action="store_true", help="Run differential integrity audit against baseline")
    parser.add_argument("-c", "--config", help="Path to monitored targets configuration", default="config/targets.json")
    parser.add_argument("-db", "--database", help="Path to store baseline database", default="baseline.db")
    args = parser.parse_args()

    display_banner()
    targets = load_config(args.config)

    if args.init:
        generate_baseline(targets, args.database)
    elif args.scan:
        perform_scan(targets, args.database)
    else:
        perform_scan(targets, args.database)

if __name__ == "__main__":
    main()
