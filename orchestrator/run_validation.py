#!/usr/bin/env python3
"""
REDFORGE — Orchestrator
Pipeline completo: Recon → Vuln Analysis → Exploitation
Author: mariobelim3

Como funciona:
  Um único comando corre todo o ciclo de pentest automaticamente:
  1. Port Scanner    — descobre portos e serviços abertos
  2. Vuln Scanner    — encontra CVEs para cada serviço
  3. Exploitation    — tenta explorar vulnerabilidades encontradas
  4. Report          — gera sumário do resultado completo
"""

import sys
import json
import time
import importlib.util
from datetime import datetime
from pathlib import Path

# ── Adiciona o root do projeto ao path ───────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from attacks.recon.port_scanner import run_scan
from attacks.recon.vuln_scanner import run_vuln_scan
from attacks.exploitation.vsftpd_234 import run_exploit as vsftpd_exploit
from attacks.exploitation.ssh_bruteforce import run_bruteforce

# ── Configuração ──────────────────────────────────────────────────────────────

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Mapeamento de serviços a exploits disponíveis
EXPLOIT_MAP = {
    21:  "vsftpd",      # FTP — vsftpd 2.3.4 backdoor
    22:  "ssh_brute",   # SSH — brute force
    139: "samba",       # SMB — usermap_script (requer Metasploit)
    445: "samba",
}

# ── Orquestrador ──────────────────────────────────────────────────────────────

def print_banner():
    print("""
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝█████╗  ██║  ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║  ██║███████╗██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    Automated Red Team Toolkit — Full Pipeline
    """)


def phase_header(phase: str):
    print(f"\n{'═' * 50}")
    print(f"  {phase}")
    print(f"{'═' * 50}")


def run_pipeline(target: str) -> dict:
    """Corre o pipeline completo de pentest."""

    print_banner()
    print(f"[*] Alvo    : {target}")
    print(f"[*] Início  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    pipeline_result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "phases": {}
    }

    # ── FASE 1: Port Scanner ──────────────────────────────────────────────────
    phase_header("FASE 1 — RECONHECIMENTO")
    scan_results = run_scan(target)
    pipeline_result["phases"]["recon"] = scan_results

    # Guarda resultado do scan
    scan_file = REPORTS_DIR / f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(scan_file, "w") as f:
        json.dump(scan_results, f, indent=4)

    open_ports = [p["port"] for p in scan_results.get("open_ports", [])]
    print(f"\n[*] Portos abertos: {open_ports}")

    # ── FASE 2: Vuln Scanner ──────────────────────────────────────────────────
    phase_header("FASE 2 — ANÁLISE DE VULNERABILIDADES")
    vuln_results = run_vuln_scan(str(scan_file))
    pipeline_result["phases"]["vulns"] = vuln_results

    # Mostra top 3 CVEs mais críticos
    top_vulns = vuln_results.get("vulnerabilities", [])[:3]
    if top_vulns:
        print(f"\n[*] Top CVEs encontrados:")
        for v in top_vulns:
            print(f"    → {v['cve_id']} | CVSS {v['cvss_score']} | Porto {v['port']}")

    # ── FASE 3: Exploração automática ────────────────────────────────────────
    phase_header("FASE 3 — EXPLORAÇÃO AUTOMÁTICA")
    exploitation_results = []

    for port in open_ports:
        if port not in EXPLOIT_MAP:
            continue

        exploit_name = EXPLOIT_MAP[port]
        print(f"\n[*] Porto {port} — a tentar exploit: {exploit_name}")

        if exploit_name == "vsftpd" and port == 21:
            result = vsftpd_exploit(target)
            exploitation_results.append(result)

        elif exploit_name == "ssh_brute" and port == 22:
            result = run_bruteforce(target)
            exploitation_results.append({
                "exploit": "ssh_bruteforce",
                "target": target,
                "success": result["success"],
                "credentials_found": result.get("found", [])
            })

        elif exploit_name == "samba":
            print(f"  [!] Samba exploit requer Metasploit — documenta manualmente")
            exploitation_results.append({
                "exploit": "samba_usermap",
                "cve": "CVE-2007-2447",
                "target": target,
                "success": "manual",
                "note": "Requer Metasploit — confirmado manualmente"
            })

    pipeline_result["phases"]["exploitation"] = exploitation_results

    # ── SUMÁRIO FINAL ────────────────────────────────────────────────────────
    phase_header("SUMÁRIO DO PIPELINE")

    successful = [e for e in exploitation_results if e.get("success") == True]
    total_cves = len(vuln_results.get("vulnerabilities", []))

    print(f"\n  Alvo              : {target}")
    print(f"  Portos abertos    : {len(open_ports)}")
    print(f"  CVEs encontrados  : {total_cves}")
    print(f"  Exploits tentados : {len(exploitation_results)}")
    print(f"  Exploits OK       : {len(successful)}")
    print(f"  Fim               : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    pipeline_result["summary"] = {
        "open_ports": len(open_ports),
        "cves_found": total_cves,
        "exploits_attempted": len(exploitation_results),
        "exploits_successful": len(successful)
    }

    # Guarda resultado completo do pipeline
    output_file = REPORTS_DIR / f"pipeline_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(pipeline_result, f, indent=4)

    print(f"\n[*] Relatório completo guardado em: {output_file}\n")

    return pipeline_result


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 orchestrator/run_validation.py <alvo>")
        print("Exemplo: python3 orchestrator/run_validation.py 10.0.2.5")
        sys.exit(1)

    target = sys.argv[1]
    run_pipeline(target)