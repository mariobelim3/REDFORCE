#!/usr/bin/env python3
"""
REDFORGE — Phase 6: Automatic Report Generator
Author: mariobelim3

Como funciona:
  Lê todos os JSONs gerados nas fases anteriores e gera
  automaticamente um relatório profissional em Markdown
  com sumário executivo, vulnerabilidades, evidências e recomendações.
"""

import json
import sys
import glob
from datetime import datetime
from pathlib import Path

# ── Configuração ──────────────────────────────────────────────────────────────

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Severidade por CVSS score
def cvss_to_severity(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "🔴 CRÍTICO"
        if s >= 7.0: return "🟠 ALTO"
        if s >= 4.0: return "🟡 MÉDIO"
        return "🟢 BAIXO"
    except:
        return "⚪ N/A"


# ── Funções de leitura ────────────────────────────────────────────────────────

def load_latest_json(pattern: str) -> dict:
    """Carrega o JSON mais recente que corresponde ao padrão."""
    files = sorted(glob.glob(str(REPORTS_DIR / pattern)))
    if not files:
        return {}
    with open(files[-1]) as f:
        return json.load(f)


def load_all_json(pattern: str) -> list:
    """Carrega todos os JSONs que correspondem ao padrão."""
    files = sorted(glob.glob(str(REPORTS_DIR / pattern)))
    results = []
    for file in files:
        with open(file) as f:
            results.append(json.load(f))
    return results


# ── Gerador de relatório ──────────────────────────────────────────────────────

def generate_report(target: str) -> str:
    """Gera o relatório completo em Markdown."""

    now = datetime.now()
    report_date = now.strftime("%d/%m/%Y %H:%M")

    # Carrega dados de cada fase
    scan_data   = load_latest_json(f"scan_{target}_*.json")
    vuln_data   = load_latest_json(f"vulns_{target}_*.json")
    brute_data  = load_latest_json(f"bruteforce_{target}_*.json")
    post_data   = load_latest_json(f"post_{target}_*.json")
    pipe_data   = load_latest_json(f"pipeline_{target}_*.json")

    open_ports  = scan_data.get("open_ports", [])
    vulns       = vuln_data.get("vulnerabilities", [])
    creds_found = brute_data.get("found", [])
    critical    = [v for v in vulns if float(v.get("cvss_score", 0) or 0) >= 9.0]

    # ── Cabeçalho ─────────────────────────────────────────────────────────────
    report = f"""# 🔴 REDFORGE — Relatório de Pentest

**Confidencial — Uso exclusivo em ambiente de laboratório**

---

## 📋 Sumário Executivo

| Campo | Detalhe |
|-------|---------|
| **Alvo** | `{target}` |
| **Data** | {report_date} |
| **Metodologia** | PTES (Penetration Testing Execution Standard) |
| **Ferramentas** | REDFORGE Toolkit (Python) |
| **Classificação** | Confidencial |

### Resultado Geral

> ⚠️ O sistema alvo apresenta **{len(critical)} vulnerabilidade(s) crítica(s)** e **{len(creds_found)} credencial(ais) comprometida(s)**. O risco global é avaliado como **CRÍTICO**.

---

## 1. Reconhecimento (T1046)

**{len(open_ports)} portos abertos** encontrados no alvo `{target}`:

| Porto | Estado | Banner |
|-------|--------|--------|
"""

    for p in open_ports:
        banner = (p.get("banner") or "—")[:60]
        report += f"| {p['port']}/tcp | 🟢 Aberto | `{banner}` |\n"

    # ── Vulnerabilidades ──────────────────────────────────────────────────────
    report += f"""
---

## 2. Vulnerabilidades Encontradas

**{len(vulns)} CVEs** identificados, ordenados por criticidade:

| CVE | CVSS | Severidade | Porto | Descrição |
|-----|------|-----------|-------|-----------|
"""

    for v in vulns:
        severity = cvss_to_severity(v.get("cvss_score"))
        desc = (v.get("description") or "—")[:80]
        report += f"| {v['cve_id']} | {v['cvss_score']} | {severity} | {v['port']} | {desc}... |\n"

    # ── Exploração ────────────────────────────────────────────────────────────
    report += """
---

## 3. Exploração

### 3.1 vsftpd 2.3.4 Backdoor (CVE-2011-2523)

- **CVSS:** 9.8 (CRÍTICO)
- **Resultado:** ✅ Acesso ROOT obtido
- **Técnica MITRE:** T1210 — Exploitation of Remote Services
- **Detalhe:** Payload `:)` enviado no campo username FTP ativa backdoor na porta 6200

### 3.2 Samba usermap_script (CVE-2007-2447)

- **CVSS:** 9.3 (CRÍTICO)
- **Resultado:** ✅ Shell ROOT obtida via Metasploit
- **Técnica MITRE:** T1210 — Exploitation of Remote Services
- **Detalhe:** Metacaracteres shell injetados no username SMB executam comandos como root

### 3.3 SSH Brute Force (T1110.001)

"""

    if creds_found:
        report += f"- **Resultado:** ✅ {len(creds_found)} credencial(ais) encontrada(s)\n\n"
        report += "| Username | Password |\n|----------|----------|\n"
        for c in creds_found:
            report += f"| `{c['username']}` | `{c['password']}` |\n"
    else:
        report += "- **Resultado:** ❌ Nenhuma credencial encontrada\n"

    # ── Pós-exploração ────────────────────────────────────────────────────────
    report += """
---

## 4. Pós-Exploração

"""
    if post_data:
        exfil = post_data.get("exfiltration", [])
        accessible = [f for f in exfil if f.get("accessible")]
        report += f"- **Ligação SSH:** ✅ Estabelecida com `{post_data.get('credentials_used', {}).get('username')}:{post_data.get('credentials_used', {}).get('password')}`\n"
        report += f"- **Técnicas executadas:** {len(post_data.get('enumeration', {}))}\n"
        report += f"- **Ficheiros sensíveis acessíveis:** {len(accessible)}/{len(exfil)}\n\n"

        if accessible:
            report += "| Ficheiro | Acessível |\n|----------|----------|\n"
            for f in exfil:
                status = "✅" if f["accessible"] else "❌"
                report += f"| `{f['file']}` | {status} |\n"

    # ── Recomendações ─────────────────────────────────────────────────────────
    report += """
---

## 5. Recomendações

| Prioridade | Vulnerabilidade | Ação Recomendada |
|-----------|----------------|-----------------|
| 🔴 CRÍTICO | vsftpd 2.3.4 | Atualizar para versão >= 3.0.0 imediatamente |
| 🔴 CRÍTICO | Samba < 3.0.25 | Atualizar Samba e desativar "username map script" |
| 🟠 ALTO | SSH passwords fracas | Implementar política de passwords fortes + MFA |
| 🟠 ALTO | Serviços desnecessários | Desativar FTP, Telnet, rexec — usar SSH |
| 🟡 MÉDIO | Apache desatualizado | Atualizar Apache para versão atual |
| 🟡 MÉDIO | MySQL exposto | Restringir acesso MySQL a localhost apenas |

---

## 6. Conclusão

O sistema `{target}` apresenta múltiplas vulnerabilidades críticas que permitem:

- **Acesso root remoto** sem autenticação (vsftpd, Samba)
- **Comprometimento de credenciais** por passwords fracas (SSH)
- **Acesso a ficheiros sensíveis** do sistema

**Recomenda-se correção imediata** de todas as vulnerabilidades críticas antes de qualquer exposição a redes não confiáveis.

---

*Relatório gerado automaticamente pelo REDFORGE Toolkit*
*Data: {report_date}*
*Autor: mariobelim3*
""".format(target=target, report_date=report_date)

    return report


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 orchestrator/report_generator.py <alvo>")
        print("Exemplo: python3 orchestrator/report_generator.py 10.0.2.5")
        sys.exit(1)

    target = sys.argv[1]

    print(f"[*] REDFORGE — A gerar relatório para {target}...")
    report = generate_report(target)

    # Guardar relatório em Markdown
    output_file = REPORTS_DIR / f"pentest_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[+] Relatório gerado: {output_file}")
    print(f"[*] Tamanho: {len(report)} caracteres")