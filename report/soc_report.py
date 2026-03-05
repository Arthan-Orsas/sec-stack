"""
soc_report.py — Rapport mensuel SOC-Mini YMCA

Génère un rapport PDF mensuel à partir des données Loki,
puis l'envoie par email via Mailjet.

Sections :
- Résumé exécutif
- Alertes critiques EntraID
- Consommation IA
- Activité VPN
- Top services bloqués FortiGate
- Connexions étrangères

Variables d'environnement :
Obligatoires :
- MAILJET_API_KEY
- MAILJET_SECRET_KEY
- REPORT_TO        (email destinataire)

Optionnelles :
- LOKI_URL         (défaut: http://loki:3100)
- REPORT_FROM      (défaut: grafana@ymca-services-occitanie.com)
- REPORT_DIR       (défaut: /reports)
- LOOKBACK_DAYS    (défaut: 30)
"""

import os
import json
import time
import requests
import smtplib
import base64
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# =========================================================
# Configuration
# =========================================================
LOKI_URL      = os.environ.get("LOKI_URL", "http://loki:3100")
REPORT_DIR    = os.environ.get("REPORT_DIR", "/reports")
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "30"))

MAILJET_API_KEY    = os.environ["MAILJET_API_KEY"]
MAILJET_SECRET_KEY = os.environ["MAILJET_SECRET_KEY"]
REPORT_TO          = os.environ["REPORT_TO"]
REPORT_FROM        = os.environ.get("REPORT_FROM", "grafana@ymca-services-occitanie.com")


# =========================================================
# Helpers Loki
# =========================================================
def loki_query_instant(expr: str, lookback_days: int = LOOKBACK_DAYS) -> list:
    """
    Exécute une requête Loki en mode instant sur les derniers N jours.
    Retourne la liste des résultats (vecteur de métriques).
    """
    end_ns   = int(time.time() * 1e9)
    start_ns = int((time.time() - lookback_days * 86400) * 1e9)

    params = {
        "query": expr,
        "time":  str(end_ns),
        "limit": "1000",
    }

    try:
        r = requests.get(
            f"{LOKI_URL}/loki/api/v1/query",
            params=params,
            timeout=120
        )
        r.raise_for_status()
        data = r.json()
        return data.get("data", {}).get("result", [])
    except Exception as e:
        print(f"Loki query error: {e}\nQuery: {expr}")
        return []


def loki_query_range(expr: str, lookback_days: int = LOOKBACK_DAYS, step: str = "1d") -> list:
    """
    Exécute une requête Loki en mode range.
    Retourne la liste des séries.
    """
    end_ts   = int(time.time())
    start_ts = end_ts - (lookback_days * 86400)

    params = {
        "query": expr,
        "start": str(start_ts),
        "end":   str(end_ts),
        "step":  step,
        "limit": "1000",
    }

    try:
        r = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            timeout=120
        )
        r.raise_for_status()
        data = r.json()
        return data.get("data", {}).get("result", [])
    except Exception as e:
        print(f"Loki range query error: {e}\nQuery: {expr}")
        return []


def extract_metric_value(results: list, label_key: str = None) -> dict:
    """
    Transforme les résultats Loki en dict {label: valeur}.
    Si label_key=None, retourne {"total": valeur}.
    """
    out = {}
    for r in results:
        metric = r.get("metric", {})
        value  = r.get("value", [None, "0"])
        val    = int(float(value[1])) if value and len(value) > 1 else 0

        if label_key and label_key in metric:
            out[metric[label_key]] = val
        else:
            out["total"] = out.get("total", 0) + val
    return out


def fmt_bytes(n: int) -> str:
    """Formate un nombre d'octets en unité lisible."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f} GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} kB"
    return f"{n} B"


# =========================================================
# Collecte des données
# =========================================================
def collect_data() -> dict:
    """
    Interroge Loki pour toutes les sections du rapport.
    Retourne un dict structuré avec toutes les métriques.
    """
    print("Collecting data from Loki...")
    period = f"[{LOOKBACK_DAYS * 24}h]"

    data = {}

    # ---------------------------------------------------
    # 1. EntraID — Résumé connexions
    # ---------------------------------------------------
    print("  - EntraID connexions...")

    res = loki_query_instant(
        f'sum(count_over_time({{source="entra_id", filename=~"/logs/entra_signins_.*\\.jsonl"}} | json | event_status_errorCode = "0" {period}))'
    )
    data["entraid_success"] = extract_metric_value(res).get("total", 0)

    res = loki_query_instant(
        f'sum(count_over_time({{source="entra_id", filename=~"/logs/entra_signins_.*\\.jsonl"}} | json | event_status_errorCode != "0" {period}))'
    )
    data["entraid_failures"] = extract_metric_value(res).get("total", 0)

    # ---------------------------------------------------
    # 2. EntraID — Codes d'erreur critiques
    # ---------------------------------------------------
    print("  - EntraID error codes...")

    res = loki_query_instant(
        f'sum by (errorCode) (count_over_time({{source="entra_id", filename=~"/logs/entra_signins_.*\\.jsonl"}} | json errorCode="event.status.errorCode" | errorCode != "0" {period}))'
    )
    data["entraid_error_codes"] = extract_metric_value(res, "errorCode")

    # ---------------------------------------------------
    # 3. EntraID — Top 10 utilisateurs en échec
    # ---------------------------------------------------
    print("  - EntraID top users...")

    res = loki_query_instant(
        f'topk(10, sum by (upn) (count_over_time({{source="entra_id", filename=~"/logs/entra_signins_.*\\.jsonl"}} | json upn="event.userPrincipalName", errorCode="event.status.errorCode" | errorCode != "0" {period})))'
    )
    data["entraid_top_users"] = extract_metric_value(res, "upn")

    # ---------------------------------------------------
    # 4. EntraID — Connexions étrangères
    # ---------------------------------------------------
    print("  - EntraID foreign logins...")

    res = loki_query_instant(
        f'sum by (country) (count_over_time({{source="entra_id"}} | json country="event.location.countryOrRegion" | country != "FR" | country != "" {period}))'
    )
    data["entraid_foreign"] = extract_metric_value(res, "country")

    # ---------------------------------------------------
    # 5. IA — Consommation par service
    # ---------------------------------------------------
    print("  - AI consumption...")

    res = loki_query_instant(
        f'sum by (app) (sum_over_time({{job="fortigate"}} |= "GenAI" | logfmt | unwrap sentbyte {period}))'
    )
    data["ai_volume"] = extract_metric_value(res, "app")

    res = loki_query_instant(
        f'count by (app) (sum by (srcip, app) (count_over_time({{job="fortigate"}} |= "GenAI" | logfmt | srcip != "" | app != "" {period})))'
    )
    data["ai_users"] = extract_metric_value(res, "app")

    # ---------------------------------------------------
    # 6. VPN — Activité SSL
    # ---------------------------------------------------
    print("  - VPN activity...")

    for action, key in [
        ("ssl-new-con",    "vpn_success"),
        ("ssl-login-fail", "vpn_failures"),
        ("ssl-alert",      "vpn_ssl_alerts"),
    ]:
        res = loki_query_instant(
            f'sum(count_over_time({{job="fortigate"}} | logfmt | subtype="vpn" | action="{action}" {period}))'
        )
        data[key] = extract_metric_value(res).get("total", 0)

    # ---------------------------------------------------
    # 7. FortiGate — Top services bloqués
    # ---------------------------------------------------
    print("  - FortiGate blocked services...")

    res = loki_query_instant(
        f'topk(10, sum by (service) (count_over_time({{job="fortigate"}} | logfmt | action="deny" | service != "" {period})))'
    )
    data["forti_blocked"] = extract_metric_value(res, "service")

    # ---------------------------------------------------
    # 8. FortiGate — Événements critiques par type
    # ---------------------------------------------------
    print("  - FortiGate critical events...")

    res = loki_query_instant(
        f'sum by (subtype) (count_over_time({{job="fortigate"}} | logfmt | level=~"alert|error" {period}))'
    )
    data["forti_critical"] = extract_metric_value(res, "subtype")

    print("Data collection complete.")
    return data


# =========================================================
# Génération PDF
# =========================================================
def build_pdf(data: dict, filepath: str, period_label: str) -> None:
    """
    Génère le rapport PDF SOC mensuel.
    """
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()

    # Styles personnalisés
    title_style = ParagraphStyle(
        "SOCTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "SOCSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#555555"),
        spaceAfter=20,
        alignment=TA_CENTER,
    )
    h1_style = ParagraphStyle(
        "SOCH1",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=colors.HexColor("#1a1a2e"),
        borderPad=4,
        spaceBefore=20,
        spaceAfter=10,
    )
    h2_style = ParagraphStyle(
        "SOCH2",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=colors.HexColor("#333333"),
        spaceBefore=12,
        spaceAfter=6,
    )
    normal = styles["Normal"]
    small  = ParagraphStyle("small", parent=normal, fontSize=9, textColor=colors.HexColor("#666666"))

    # Couleurs tableau
    HDR_BG   = colors.HexColor("#1a1a2e")
    HDR_FG   = colors.white
    ROW_ALT  = colors.HexColor("#f5f5f5")
    ROW_NORM = colors.white

    def make_table(headers, rows, col_widths=None):
        """Helper pour créer un tableau stylisé."""
        table_data = [[Paragraph(f"<b>{h}</b>", ParagraphStyle("th", parent=normal, fontSize=9, textColor=HDR_FG))] if isinstance(h, str) else h for h in headers]
        table_data = [headers] + rows

        t = Table(table_data, colWidths=col_widths)
        style = TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  HDR_BG),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  HDR_FG),
            ("FONTSIZE",    (0, 0), (-1, 0),  9),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [ROW_NORM, ROW_ALT]),
            ("FONTSIZE",    (0, 1), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ])
        t.setStyle(style)
        return t

    story = []

    # -------------------------------------------------------
    # PAGE DE GARDE
    # -------------------------------------------------------
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("SOC-Mini YMCA", title_style))
    story.append(Paragraph("Rapport de sécurité mensuel", subtitle_style))
    story.append(Paragraph(f"Période : {period_label}", subtitle_style))
    story.append(Paragraph(f"Généré le : {datetime.now().strftime('%d/%m/%Y à %H:%M')}", subtitle_style))
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "Ce rapport est généré automatiquement à partir des logs collectés par la stack SOC-Mini "
        "(Loki / Promtail / FortiGate / Entra ID). Les données couvrent la période indiquée ci-dessus.",
        small
    ))
    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 1 — RÉSUMÉ EXÉCUTIF
    # -------------------------------------------------------
    story.append(Paragraph("1. Résumé exécutif", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    total_auth = data["entraid_success"] + data["entraid_failures"]
    fail_rate  = (data["entraid_failures"] / total_auth * 100) if total_auth > 0 else 0
    lockouts   = data["entraid_error_codes"].get("50053", 0)
    bruteforce = data["entraid_error_codes"].get("50126", 0)
    total_ai   = sum(data["ai_volume"].values())
    foreign    = sum(data["entraid_foreign"].values())

    kpi_rows = [
        ["Connexions Entra ID réussies",  str(data["entraid_success"]),  ""],
        ["Connexions Entra ID échouées",  str(data["entraid_failures"]),  f"{fail_rate:.1f}% du total"],
        ["Comptes verrouillés (50053)",   str(lockouts),    "⚠ Critique si > 0" if lockouts > 0 else "OK"],
        ["Tentatives brute-force (50126)",str(bruteforce),  "⚠ Surveiller" if bruteforce > 30 else "Normal"],
        ["Connexions depuis l'étranger",  str(foreign),     "⚠ A qualifier" if foreign > 0 else "Aucune"],
        ["Volume total vers services IA", fmt_bytes(total_ai), ""],
        ["Tunnels VPN établis",           str(data["vpn_success"]),  ""],
        ["Échecs login VPN",              str(data["vpn_failures"]),  "⚠ Surveiller" if data["vpn_failures"] > 10 else "Normal"],
    ]

    story.append(make_table(
        ["Indicateur", "Valeur", "Interprétation"],
        kpi_rows,
        col_widths=[9*cm, 3*cm, 5.5*cm]
    ))
    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 2 — ALERTES CRITIQUES ENTRA ID
    # -------------------------------------------------------
    story.append(Paragraph("2. Alertes critiques Entra ID", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    # Codes d'erreur
    story.append(Paragraph("2.1 Top codes d'erreur", h2_style))
    ERROR_LABELS = {
        "50126": "Identifiants invalides",
        "50125": "Echec authentification",
        "50053": "Compte verrouillé",
        "50055": "Mot de passe expiré",
        "50057": "Compte désactivé",
        "50074": "MFA requis / interruption",
        "50072": "MFA requis / interaction",
        "70044": "Token expiré / CA",
        "9002341": "SSO à autoriser",
    }
    error_rows = sorted(data["entraid_error_codes"].items(), key=lambda x: x[1], reverse=True)
    if error_rows:
        story.append(make_table(
            ["Code erreur", "Description", "Occurrences"],
            [[code, ERROR_LABELS.get(code, "Autre"), str(count)] for code, count in error_rows[:10]],
            col_widths=[3*cm, 10*cm, 4.5*cm]
        ))
    else:
        story.append(Paragraph("Aucune erreur détectée sur la période.", normal))

    story.append(Spacer(1, 0.5*cm))

    # Top utilisateurs en échec
    story.append(Paragraph("2.2 Top utilisateurs avec échecs d'authentification", h2_style))
    user_rows = sorted(data["entraid_top_users"].items(), key=lambda x: x[1], reverse=True)
    if user_rows:
        story.append(make_table(
            ["Utilisateur", "Échecs"],
            [[upn, str(count)] for upn, count in user_rows[:10]],
            col_widths=[13*cm, 4.5*cm]
        ))
    else:
        story.append(Paragraph("Aucun échec utilisateur significatif.", normal))

    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 3 — CONNEXIONS ÉTRANGÈRES
    # -------------------------------------------------------
    story.append(Paragraph("3. Connexions depuis l'étranger", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    if data["entraid_foreign"]:
        foreign_rows = sorted(data["entraid_foreign"].items(), key=lambda x: x[1], reverse=True)
        story.append(make_table(
            ["Pays", "Connexions"],
            [[country, str(count)] for country, count in foreign_rows],
            col_widths=[13*cm, 4.5*cm]
        ))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "Note : Une connexion étrangère peut être légitime (VPN, déplacement) ou indiquer "
            "une compromission de compte. Chaque occurrence doit être qualifiée.",
            small
        ))
    else:
        story.append(Paragraph("Aucune connexion depuis l'étranger détectée sur la période.", normal))

    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 4 — CONSOMMATION IA
    # -------------------------------------------------------
    story.append(Paragraph("4. Consommation des services IA", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    all_apps = set(list(data["ai_volume"].keys()) + list(data["ai_users"].keys()))
    if all_apps:
        ai_rows = []
        for app in sorted(all_apps):
            volume = data["ai_volume"].get(app, 0)
            users  = data["ai_users"].get(app, 0)
            ai_rows.append([app, fmt_bytes(volume), str(users)])
        ai_rows.sort(key=lambda x: data["ai_volume"].get(x[0], 0), reverse=True)

        story.append(make_table(
            ["Service IA", "Volume envoyé (sentbyte)", "Postes distincts"],
            ai_rows,
            col_widths=[7*cm, 6*cm, 4.5*cm]
        ))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "Volume total envoyé vers les services IA : " + fmt_bytes(total_ai),
            normal
        ))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            "Un volume élevé peut indiquer une utilisation intensive ou un risque de fuite "
            "de données sensibles. Croiser avec la politique d'usage des outils IA de l'organisation.",
            small
        ))
    else:
        story.append(Paragraph("Aucune consommation IA détectée sur la période.", normal))

    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 5 — ACTIVITÉ VPN
    # -------------------------------------------------------
    story.append(Paragraph("5. Activité VPN SSL", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    vpn_rows = [
        ["Tunnels établis (ssl-new-con)",      str(data["vpn_success"]),    "Connexions légitimes"],
        ["Échecs login (ssl-login-fail)",       str(data["vpn_failures"]),   "⚠ Tentatives échouées" if data["vpn_failures"] > 10 else "Normal"],
        ["Erreurs SSL (ssl-alert/exit-error)", str(data["vpn_ssl_alerts"]), "Bruit de fond internet (scanners)"],
    ]
    story.append(make_table(
        ["Événement", "Occurrences", "Interprétation"],
        vpn_rows,
        col_widths=[7*cm, 3.5*cm, 7*cm]
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Les erreurs SSL (ssl-alert) sont typiquement du bruit de fond internet — des scanners automatiques "
        "qui sondent les VPN Fortinet exposés. Un volume élevé d'échecs login mérite investigation.",
        small
    ))

    story.append(PageBreak())

    # -------------------------------------------------------
    # SECTION 6 — TOP SERVICES BLOQUÉS
    # -------------------------------------------------------
    story.append(Paragraph("6. Top services bloqués FortiGate", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    if data["forti_blocked"]:
        blocked_rows = sorted(data["forti_blocked"].items(), key=lambda x: x[1], reverse=True)
        story.append(make_table(
            ["Service / Application", "Blocages"],
            [[svc, str(count)] for svc, count in blocked_rows],
            col_widths=[13*cm, 4.5*cm]
        ))
    else:
        story.append(Paragraph("Aucun service bloqué détecté sur la période.", normal))

    story.append(Spacer(1, 0.5*cm))

    # Événements critiques
    story.append(Paragraph("6.1 Événements critiques FortiGate (level=alert/error)", h2_style))
    if data["forti_critical"]:
        crit_rows = sorted(data["forti_critical"].items(), key=lambda x: x[1], reverse=True)
        story.append(make_table(
            ["Sous-type", "Occurrences"],
            [[subtype, str(count)] for subtype, count in crit_rows],
            col_widths=[13*cm, 4.5*cm]
        ))
    else:
        story.append(Paragraph("Aucun événement critique détecté.", normal))

    # -------------------------------------------------------
    # PIED DE PAGE
    # -------------------------------------------------------
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Rapport généré automatiquement par SOC-Mini YMCA • {datetime.now().strftime('%d/%m/%Y')} • "
        "Données issues de Loki / FortiGate / Microsoft Entra ID",
        ParagraphStyle("footer", parent=normal, fontSize=8, textColor=colors.HexColor("#999999"), alignment=TA_CENTER)
    ))

    # Build
    doc.build(story)
    print(f"PDF generated: {filepath}")


# =========================================================
# Envoi email via Mailjet
# =========================================================
def send_email(pdf_path: str, period_label: str) -> None:
    """
    Envoie le rapport PDF par email via Mailjet (SMTP).
    """
    msg = MIMEMultipart()
    msg["From"]    = REPORT_FROM
    msg["To"]      = REPORT_TO
    msg["Subject"] = f"[SOC-Mini YMCA] Rapport mensuel - {period_label}"

    body = MIMEText(
        f"Bonjour,\n\n"
        f"Veuillez trouver en pièce jointe le rapport de sécurité mensuel SOC-Mini YMCA "
        f"pour la période : {period_label}.\n\n"
        f"Ce rapport a été généré automatiquement à partir des données Loki.\n\n"
        f"Cordialement,\nSOC-Mini YMCA",
        "plain"
    )
    msg.attach(body)

    with open(pdf_path, "rb") as f:
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(f.read())
        encoders.encode_base64(attachment)
        filename = os.path.basename(pdf_path)
        attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(attachment)

    with smtplib.SMTP("in-v3.mailjet.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.login(MAILJET_API_KEY, MAILJET_SECRET_KEY)
        server.sendmail(REPORT_FROM, REPORT_TO, msg.as_string())

    print(f"Email sent to {REPORT_TO}")


# =========================================================
# Main
# =========================================================
def main() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)

    # Période du rapport
    now       = datetime.now(timezone.utc)
    last_month = now - timedelta(days=LOOKBACK_DAYS)
    period_label = f"{last_month.strftime('%d/%m/%Y')} - {now.strftime('%d/%m/%Y')}"

    filename = f"soc-report-{now.strftime('%Y-%m')}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    print(f"=== SOC-Mini Report Generator ===")
    print(f"Period : {period_label}")
    print(f"Output : {filepath}")

    # Collecte
    data = collect_data()

    # Génération PDF
    build_pdf(data, filepath, period_label)

    # Envoi email
    send_email(filepath, period_label)

    print("=== Report done ===")


if __name__ == "__main__":
    main()
