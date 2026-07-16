<div align="center">

# 🔴 REDFORGE

**Automated Red Team Toolkit in Python**

*Full pentest cycle — Recon → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting*

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-%20Concluído-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Lab](https://img.shields.io/badge/Lab-VirtualBox%20%7C%20Kali%20%7C%20Metasploitable2-blueviolet?style=flat-square)

</div>

---

## ⚠️ Aviso Legal

> Este toolkit foi desenvolvido **exclusivamente para fins educativos e de investigação**.
> Todos os testes são realizados em ambiente de laboratório isolado e controlado, contra máquinas **próprias ou com autorização explícita**.
> A utilização deste software em sistemas sem autorização é **ilegal e antiética**.

---

## 📌 Sobre o Projeto

O **REDFORGE** é um toolkit de Red Team desenvolvido em Python que automatiza o ciclo completo de um pentest — desde o reconhecimento inicial até à geração automática de um relatório profissional.

O projeto foi construído como portfólio prático de cibersegurança, com foco em:

- Desenvolver ferramentas ofensivas de raiz (não wrappers de ferramentas existentes)
- Mapear cada técnica ao framework **MITRE ATT&CK**
- Gerar relatórios de pentest no formato utilizado em contexto profissional

---
## 🏗️ Arquitetura

```
REDFORGE/
├── attacks/              # Scripts de ataque por técnica MITRE ATT&CK
│   ├── recon/            #   T1046 — Network Service Scanning
│   ├── exploitation/     #   T1110 — Brute Force, exploits específicos
│   └── post/             #   T1083 — File Discovery, exfiltração
├── orchestrator/         # Motor principal — corre o ciclo completo em cadeia
├── reports/              # Relatórios gerados automaticamente (PDF/Markdown)
├── docs/                 # Documentação técnica e mapeamento MITRE
└── requirements.txt
```

## 🔁 Fluxo de Execução

| Passo | Módulo | Descrição |
|-------|--------|-----------|
| 1 | Recon | Scanner de portas e banner grabbing (sockets) |
| 2 | Vuln Analysis | CVE lookup via NVD API + score CVSS |
| 3 | Exploitation | vsftpd, Samba, distcc, brute force (Paramiko) |
| 4 | Post-Exploitation | Enumeração pós-acesso, exfiltração simulada |
| 5 | Report | Geração automática de relatório PDF/Markdown |

## 🧪 Ambiente de Laboratório

| Componente       | Função                        |
|-----------------|-------------------------------|
| Kali Linux      | Máquina atacante               |
| Metasploitable2 | Alvo principal (vulnerável)    |
| Wazuh           | Monitorização e deteção (SIEM) |
| VirtualBox      | Hypervisor (rede interna NAT)  |

> Infraestrutura documentada no repositório [home-lab] (https://github.com/mariobelim3/homelab-cybersecurity)

---

## 🗺️ Roadmap

| Fase | Descrição | Estado |
|------|-----------|--------|
| 0 | Preparação do lab e estrutura do repositório | ✅ Concluído |
| 1 | Reconhecimento (scanner de portas, banner grabbing) | ✅ Concluído |
| 2 | Análise de vulnerabilidades (CVE lookup, CVSS) | ✅ Concluído |
| 3 | Exploração (vsftpd, Samba, distcc, brute force) | ✅ Concluído |
| 4 | Orquestrador (pipeline recon → exploit) | ✅ Concluído |
| 5 | Pós-exploração (privesc, exfiltração simulada) | ✅ Concluído |
| 6 | Reporting automático (PDF/Markdown profissional) | ✅ Concluído |

---

## 📸 Evidências

### Fase 1 — Reconhecimento

![port scanner](docs/screenshots/phase1_port_scanner.png)

### Fase 2 — Análise de Vulnerabilidades

![vuln scanner](docs/screenshots/phase2_vuln_scanner.png)

### Fase 3 — Exploração

**vsftpd 2.3.4 Backdoor (CVE-2011-2523 | CVSS 9.8 CRITICAL)**

![vsftpd exploit](docs/screenshots/phase3_vsftpd_exploit.png)

**Samba usermap_script RCE (CVE-2007-2447 | CVSS 9.3 CRITICAL)**

![samba usermap](docs/screenshots/phase3_samba_usermap.png)

**SSH Brute Force (T1110.001) — 4 credenciais encontradas**

![ssh bruteforce](docs/screenshots/phase3_ssh_bruteforce.png)

### Fase 4 — Orquestrador

**Pipeline completo: Recon → Vuln Analysis → Exploitation**

![pipeline 1](docs/screenshots/phase4_orchestrator_1.png)
![pipeline 2](docs/screenshots/phase4_orchestrator_2.png)
![pipeline 3](docs/screenshots/phase4_orchestrator_3.png)
![pipeline 4](docs/screenshots/phase4_orchestrator_4.png)

### Fase 5 — Pós-Exploração

**Enumeração e Exfiltração Simulada (T1083, T1057, T1087, T1048, T1049)**

![post exploitation 1](docs/screenshots/phase5_post_exploitation_1.png)
![post exploitation 2](docs/screenshots/phase5_post_exploitation_2.png)

### Fase 6 — Reporting Automático

**Relatório profissional gerado automaticamente em Markdown**

![report 1](docs/screenshots/phase6_report_1.png)
![report 2](docs/screenshots/phase6_report_2.png)
![report 3](docs/screenshots/phase6_report_3.png)
![report 4](docs/screenshots/phase6_report_4.png)

## 🛠️ Stack Técnico

- **Python 3.10+** — linguagem principal
- **Scapy / sockets** — recon e scanning
- **Paramiko** — ataques SSH
- **Requests** — integração com APIs (NVD, Wazuh)
- **ReportLab / Markdown** — geração de relatórios

---

## 👤 Autor

**Mário** · Estudante de Engenharia Informática — Universidade da Madeira  
Área de interesse: Cibersegurança & Redes  
GitHub: [@mariobelim3](https://github.com/mariobelim3)
