#!/usr/bin/env python3
"""
REDFORGE — Phase 2: Vulnerability Scanner
Technique: T1592 — Gather Victim Host Information
Author: mariobelim3
"""

import json
import requests
import sys
import time
from datetime import datetime

# ── Configuração ──────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DELAY = 6  # segundos entre pedidos à API (limite do NVD sem API key)

# Mapeamento de serviços conhecidos para termos de pesquisa no NVD
SERVICE_KEYWORDS = {
    "vsftpd 2.3.4": "vsftpd 2.3.4",
    "openssh 4.7": "OpenSSH 4.7",
    "apache": "Apache HTTP Server",
    "samba": "Samba",
    "mysql": "MySQL 5.0",
    "postfix": "Postfix",
    "vnc": "VNC",
}

# ── Funções ───────────────────────────────────────────────────────────────────

def load_scan_results(json_file: str) -> dict:
    """Carrega o ficheiro JSON gerado pelo port_scanner."""
    with open(json_file, "r") as f:
        return json.load(f)


def extract_service_keywords(banner: str) -> list[str]:
    """Extrai palavras-chave do banner para pesquisar no NVD."""
    keywords = []
    banner_lower = banner.lower()

    for key, search_term in SERVICE_KEYWORDS.items():
        if key.lower() in banner_lower:
            keywords.append(search_term)

    return keywords if keywords else []


def query_nvd(keyword: str) -> list[dict]:
    """Consulta a API do NVD e devolve lista de CVEs."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,  # top 5 CVEs por serviço
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            # Obter score CVSS (v3 preferencial, v2 como fallback)
            cvss_score = "N/A"
            cvss_severity = "N/A"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", "N/A")
                cvss_severity = cvss_data.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", "N/A")
                cvss_severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

            # Obter descrição
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"), "N/A"
            )

            cves.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "description": description[:200],
            })

        return cves

    except requests.RequestException as e:
        print(f"  [!] Erro ao consultar NVD: {e}")
        return []


def run_vuln_scan(scan_file: str) -> dict:
    """Motor principal — analisa o scan e consulta CVEs para cada serviço."""

    print(f"\n[*] REDFORGE — Vulnerability Scanner")
    print(f"[*] Ficheiro : {scan_file}")
    print(f"[*] Início   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─' * 50}")

    # Carrega resultados do port scanner
    scan_data = load_scan_results(scan_file)
    target = scan_data.get("target", "unknown")
    open_ports = scan_data.get("open_ports", [])

    results = {
        "mitre_technique": "T1592",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": []
    }

    for port_info in open_ports:
        port = port_info.get("port")
        banner = port_info.get("banner", "")

        if not banner:
            continue

        print(f"\n[*] Porto {port}/tcp — {banner[:60]}")

        # Extrai keywords do banner
        keywords = extract_service_keywords(banner)

        if not keywords:
            print(f"  [-] Sem keywords reconhecidas para este banner")
            continue

        for keyword in keywords:
            print(f"  [>] A consultar NVD: '{keyword}'")
            cves = query_nvd(keyword)

            if cves:
                for cve in cves:
                    print(f"  [+] {cve['cve_id']} | CVSS: {cve['cvss_score']} ({cve['cvss_severity']})")
                    results["vulnerabilities"].append({
                        "port": port,
                        "banner": banner[:100],
                        "keyword": keyword,
                        **cve
                    })
            else:
                print(f"  [-] Sem CVEs encontrados")

            # Respeita o rate limit do NVD
            time.sleep(DELAY)

    # Ordena por CVSS score (mais crítico primeiro)
    results["vulnerabilities"].sort(
        key=lambda x: float(x["cvss_score"]) if x["cvss_score"] != "N/A" else 0,
        reverse=True
    )

    print(f"\n{'─' * 50}")
    print(f"[*] Total de CVEs encontrados : {len(results['vulnerabilities'])}")
    print(f"[*] Fim : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 vuln_scanner.py <ficheiro_scan.json>")
        print("Exemplo: python3 vuln_scanner.py reports/scan_10.0.2.6_*.json")
        sys.exit(1)

    scan_file = sys.argv[1]
    results = run_vuln_scan(scan_file)

    # Guardar output
    output_file = f"reports/vulns_{results['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[*] Resultados guardados em: {output_file}")