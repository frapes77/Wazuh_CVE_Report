#!/usr/bin/env python3
"""
wazuh_cve_report.py
====================

Script che genera un report PDF con l'elenco dei dispositivi
(agent Wazuh) affetti da una specifica CVE, interrogando il Wazuh Indexer
(OpenSearch) che alimenta il modulo "Vulnerability Detection" di Wazuh 4.8+.

Uso:
    python3 wazuh_cve_report.py CVE-2026-70347
    python3 wazuh_cve_report.py CVE-2026-70347 --host https://10.0.0.10:9200
    python3 wazuh_cve_report.py  (chiede la CVE a runtime)

Requisiti:
    pip install requests reportlab

Note:
    - Le credenziali richieste sono quelle dell'utente del Wazuh Indexer
      (tipicamente lo stesso "admin" usato per Kibana/Wazuh Dashboard, o un
      utente OpenSearch dedicato con permessi di lettura sull'indice
      wazuh-states-vulnerabilities-*).
    - Se il tuo Wazuh e' in versione 4.3-4.7 (Vulnerability Detector "classico",
      API Manager su porta 55000) questo script NON funziona cosi' com'è:
      in quel caso i dati vanno letti via API Manager con endpoint
      GET /vulnerability/{agent_id}, agent per agent, e non esiste una ricerca
      diretta per CVE su tutti gli host.
"""

import argparse
import getpass
import json
import sys
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ============================ CONFIGURAZIONE ============================
# Modifica questi valori di default, oppure passali da riga di comando.
DEFAULT_WAZUH_INDEXER_HOST = "https://172.16.1.172:9200"
VULN_INDEX_PATTERN = "wazuh-states-vulnerabilities-*"
VERIFY_SSL = False  # Metti True se hai certificati validi sull'Indexer
REQUEST_TIMEOUT = 30

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# ==========================================================================


def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera un report PDF dei dispositivi affetti da una CVE, "
        "interrogando il Wazuh Indexer."
    )
    parser.add_argument(
        "cve",
        nargs="?",
        help="Codice CVE da cercare (es. CVE-2026-70347). Se omesso, viene richiesto a runtime.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_WAZUH_INDEXER_HOST,
        help=f"URL del Wazuh Indexer (default: {DEFAULT_WAZUH_INDEXER_HOST})",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Nome del file PDF di output (default: report_<CVE>.pdf)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disabilita la verifica del certificato SSL dell'Indexer (default gia' disabilitata).",
    )
    parser.add_argument(
        "--no-internet",
        action="store_true",
        help="Non tentare di recuperare descrizione/remediation da NVD (usa solo dati Wazuh).",
    )
    parser.add_argument(
        "--agent",
        default=None,
        help="Filtra la ricerca su un singolo agent (per nome), utile per debug "
        "quando un dispositivo che ti aspetti non compare nel report.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Stampa informazioni diagnostiche (totale hit ES, query inviata, "
        "eventuale campo vulnerability.status) e salva la risposta grezza in "
        "debug_response.json.",
    )
    return parser.parse_args()


def get_cve_code(args):
    cve = args.cve
    if not cve:
        cve = input("Inserisci il codice CVE (es. CVE-2026-70347): ").strip()
    cve = cve.upper().strip()
    if not cve.startswith("CVE-"):
        print("Attenzione: il codice non sembra nel formato CVE-YYYY-NNNNN, procedo comunque.")
    return cve


def get_credentials():
    print("\n=== Autenticazione Wazuh Indexer ===")
    user = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    return user, password


def query_vulnerability(host, cve_id, user, password, agent_filter=None, debug=False):
    """
    Interroga il Wazuh Indexer (OpenSearch) per ottenere tutti i documenti
    relativi alla CVE indicata, su tutti gli agent (o su un singolo agent se
    agent_filter e' specificato).
    """
    url = f"{host.rstrip('/')}/{VULN_INDEX_PATTERN}/_search"

    must_clauses = [{"term": {"vulnerability.id": cve_id}}]
    if agent_filter:
        must_clauses.append({"match": {"agent.name": agent_filter}})

    query = {
        "size": 10000,
        "_source": [
            "agent.name",
            "agent.id",
            "agent.ip",
            "package.name",
            "package.version",
            "package.architecture",
            "vulnerability.id",
            "vulnerability.description",
            "vulnerability.severity",
            "vulnerability.score.base",
            "vulnerability.published_at",
            "vulnerability.status",
        ],
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"agent.name": {"order": "asc"}}],
    }

    if debug:
        print("\n[DEBUG] Query inviata all'Indexer:")
        print(json.dumps(query, indent=2))

    try:
        resp = requests.post(
            url,
            auth=(user, password),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=VERIFY_SSL,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.SSLError as e:
        print(f"Errore SSL nel contattare l'Indexer: {e}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"Impossibile connettersi a {host}: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Errore nella richiesta all'Indexer: {e}")
        sys.exit(1)

    if resp.status_code == 401:
        print("Autenticazione fallita: username o password errati.")
        sys.exit(1)
    if resp.status_code == 404:
        print(
            f"Indice '{VULN_INDEX_PATTERN}' non trovato. Verifica che il modulo "
            "Vulnerability Detection sia attivo e che l'URL dell'Indexer sia corretto."
        )
        sys.exit(1)
    if not resp.ok:
        print(f"Errore HTTP {resp.status_code} dall'Indexer:")
        print(resp.text[:1000])
        sys.exit(1)

    result = resp.json()

    if debug:
        total = result.get("hits", {}).get("total", {})
        total_value = total.get("value", total) if isinstance(total, dict) else total
        returned = len(result.get("hits", {}).get("hits", []))
        print(f"[DEBUG] Hit totali riportati da ES/OpenSearch: {total_value}")
        print(f"[DEBUG] Hit effettivamente restituiti (limite size=1000): {returned}")
        agent_names = sorted(
            {
                h.get("_source", {}).get("agent", {}).get("name", "N/D")
                for h in result.get("hits", {}).get("hits", [])
            }
        )
        print(f"[DEBUG] Agent trovati per questa CVE: {agent_names}")
        with open("debug_response.json", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print("[DEBUG] Risposta completa salvata in debug_response.json\n")

    return result


def extract_devices(raw_response):
    """
    Estrae dall'output di OpenSearch l'elenco dei dispositivi affetti,
    deduplicando per agent + package (puo' capitare piu' pacchetti vulnerabili
    per lo stesso agent).
    """
    hits = raw_response.get("hits", {}).get("hits", [])
    devices = []
    seen = set()
    vuln_meta = {}

    for hit in hits:
        src = hit.get("_source", {})
        agent = src.get("agent", {})
        package = src.get("package", {})
        vuln = src.get("vulnerability", {})

        agent_name = agent.get("name", "N/D")
        agent_ip = agent.get("ip", "N/D")
        pkg_name = package.get("name", "N/D")
        pkg_version = package.get("version", "N/D")

        key = (agent_name, pkg_name, pkg_version)
        if key in seen:
            continue
        seen.add(key)

        devices.append(
            {
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "package_name": pkg_name,
                "package_version": pkg_version,
                "severity": vuln.get("severity", "N/D"),
                "status": vuln.get("status", "N/D"),
            }
        )

        # Conserviamo i metadati della vulnerabilita' (uguali per tutti i document,
        # li prendiamo dal primo che troviamo)
        if not vuln_meta:
            vuln_meta = {
                "description": vuln.get("description", ""),
                "severity": vuln.get("severity", "N/D"),
                "score": vuln.get("score", {}).get("base", "N/D"),
                "published_at": vuln.get("published_at", "N/D"),
            }

    devices.sort(key=lambda d: d["agent_name"])
    return devices, vuln_meta


def fetch_nvd_info(cve_id):
    """
    Recupera da NVD (nist.gov) descrizione e riferimenti/remediation per la CVE,
    da usare come fallback o integrazione se Wazuh non riporta una descrizione
    utile. Ritorna un dizionario, o None se non disponibile.
    """
    try:
        resp = requests.get(
            NVD_API_URL, params={"cveId": cve_id}, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        descriptions = cve_data.get("descriptions", [])
        description_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        metrics = cve_data.get("metrics", {})
        base_score = None
        severity = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss = metrics[metric_key][0].get("cvssData", {})
                base_score = cvss.get("baseScore")
                severity = metrics[metric_key][0].get(
                    "baseSeverity", cvss.get("baseSeverity")
                )
                break

        references = [
            ref.get("url")
            for ref in cve_data.get("references", [])
            if ref.get("url")
        ][:5]

        return {
            "description": description_en,
            "score": base_score,
            "severity": severity,
            "references": references,
        }
    except requests.exceptions.RequestException as e:
        print(f"Avviso: impossibile contattare NVD per informazioni aggiuntive ({e}).")
        return None
    except (KeyError, IndexError, ValueError) as e:
        print(f"Avviso: risposta NVD inattesa, la ignoro ({e}).")
        return None


def build_recommended_actions(devices, nvd_info):
    """
    Costruisce una lista di azioni raccomandate: usa i riferimenti NVD se
    disponibili, altrimenti fornisce raccomandazioni generiche basate sui
    pacchetti coinvolti.
    """
    actions = []

    packages = sorted({d["package_name"] for d in devices if d["package_name"] != "N/D"})
    if packages:
        pkg_list = ", ".join(packages)
        actions.append(
            f"Aggiornare il/i pacchetto/i interessato/i ({pkg_list}) all'ultima versione "
            "disponibile fornita dal vendor/distribuzione, che risolve la vulnerabilita' indicata."
        )
    else:
        actions.append(
            "Aggiornare il software interessato all'ultima versione disponibile fornita dal vendor."
        )

    actions.append(
        "Verificare la disponibilita' di patch di sicurezza ufficiali e pianificarne "
        "l'installazione nella prossima finestra di manutenzione."
    )
    actions.append(
        "Se una patch non e' immediatamente disponibile, valutare misure di mitigazione "
        "temporanee (es. restrizione dell'accesso di rete al servizio vulnerabile, "
        "disabilitazione della funzionalita' interessata se non essenziale)."
    )
    actions.append(
        "Ripetere la scansione con Wazuh dopo l'applicazione delle patch per confermare "
        "la risoluzione della vulnerabilita' sui dispositivi elencati."
    )

    if nvd_info and nvd_info.get("references"):
        actions.append("Riferimenti utili (NVD):")
        for ref in nvd_info["references"]:
            actions.append(f"  - {ref}")

    return actions


# ============================== GENERAZIONE PDF ==============================

def make_box(title, body_flowables, bg_color=colors.HexColor("#EAF1FB")):
    """
    Crea un 'riquadro' visivo: una Table a una colonna con sfondo colorato,
    bordo e padding, contenente un titolo e uno o piu' Paragraph/flowable.
    """
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "BoxTitle",
        parent=styles["Heading3"],
        textColor=colors.HexColor("#1F3864"),
        spaceAfter=6,
    )

    content = [Paragraph(title, title_style)] + body_flowables
    table = Table([[content]], colWidths=[17 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#B4C7E7")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def generate_pdf(cve_id, vuln_meta, nvd_info, devices, recommended_actions, output_path):
    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"], alignment=TA_LEFT, fontSize=10, leading=14
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    elements = []

    # --- Titolo ---
    title_style = ParagraphStyle(
        "MainTitle", parent=styles["Title"], textColor=colors.HexColor("#1F3864")
    )
    elements.append(Paragraph(f"Report Vulnerabilita' - {cve_id}", title_style))
    elements.append(
        Paragraph(
            f"Generato il {datetime.now().strftime('%d/%m/%Y %H:%M')}",
            ParagraphStyle("Subtitle", parent=styles["Normal"], textColor=colors.grey),
        )
    )
    elements.append(Spacer(1, 0.6 * cm))

    # --- Riquadro 1: descrizione CVE ---
    description = ""
    severity = "N/D"
    score = "N/D"
    if vuln_meta and vuln_meta.get("description"):
        description = vuln_meta["description"]
        severity = vuln_meta.get("severity", "N/D")
        score = vuln_meta.get("score", "N/D")
    elif nvd_info and nvd_info.get("description"):
        description = nvd_info["description"]
        severity = nvd_info.get("severity") or severity
        score = nvd_info.get("score") or score

    if not description:
        description = "Descrizione non disponibile ne' da Wazuh ne' da NVD per questa CVE."

    box1_body = [
        Paragraph(f"<b>Severity:</b> {severity} &nbsp;&nbsp; <b>CVSS Score:</b> {score}", body_style),
        Spacer(1, 6),
        Paragraph(description, body_style),
    ]
    elements.append(make_box(f"CVE: {cve_id}", box1_body))
    elements.append(Spacer(1, 0.5 * cm))

    # --- Riquadro 2: Recommended Actions ---
    box2_body = []
    for action in recommended_actions:
        box2_body.append(Paragraph(f"&bull; {action}", body_style))
        box2_body.append(Spacer(1, 3))
    elements.append(
        make_box("Recommended Actions", box2_body, bg_color=colors.HexColor("#FDF2E3"))
    )
    elements.append(Spacer(1, 0.7 * cm))

    # --- Tabella dispositivi affetti ---
    elements.append(Paragraph(f"Dispositivi affetti ({len(devices)})", styles["Heading2"]))
    elements.append(Spacer(1, 0.3 * cm))

    if devices:
        table_data = [["Dispositivo", "Sistema Operativo (package.name)", "Versione (package.version)"]]
        for d in devices:
            table_data.append(
                [d["agent_name"], d["package_name"], d["package_version"]]
            )

        devices_table = Table(
            table_data, colWidths=[5 * cm, 8.5 * cm, 3.5 * cm], repeatRows=1
        )
        devices_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B4C7E7")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F6FC")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(devices_table)
    else:
        elements.append(
            Paragraph(
                "Nessun dispositivo risulta attualmente affetto da questa CVE.",
                body_style,
            )
        )

    doc.build(elements)


def main():
    args = parse_args()

    global VERIFY_SSL
    if args.insecure:
        VERIFY_SSL = False

    cve_id = get_cve_code(args)
    user, password = get_credentials()

    print(f"\nInterrogo il Wazuh Indexer ({args.host}) per la CVE {cve_id}...")
    raw = query_vulnerability(
        args.host, cve_id, user, password, agent_filter=args.agent, debug=args.debug
    )

    devices, vuln_meta = extract_devices(raw)
    print(f"Trovati {len(devices)} dispositivi/pacchetti affetti.")

    nvd_info = None
    if not args.no_internet:
        print("Recupero informazioni aggiuntive da NVD...")
        nvd_info = fetch_nvd_info(cve_id)

    recommended_actions = build_recommended_actions(devices, nvd_info)

    output_path = args.output or f"report_{cve_id}.pdf"
    generate_pdf(cve_id, vuln_meta, nvd_info, devices, recommended_actions, output_path)

    print(f"\nReport generato con successo: {output_path}")


if __name__ == "__main__":
    main()
