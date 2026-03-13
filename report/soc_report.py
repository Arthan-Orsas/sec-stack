"""
soc_report.py — Rapport mensuel SOC-Mini YMCA

STRATÉGIE LOKI :
- Loki refuse les fenêtres > 24h en mode instant (erreur 400)
- Les grandes fenêtres en range timeout sur FortiGate
- Solution : on découpe la période en tranches de 24h et on additionne
  → loki_query_chunked() fait N appels instant [24h] glissants
  → léger, fiable, pas de timeout

Variables d'environnement :
Obligatoires : MAILJET_API_KEY, MAILJET_SECRET_KEY, REPORT_TO
Optionnelles : LOKI_URL, REPORT_FROM, REPORT_DIR, LOOKBACK_DAYS
"""

import os
import json
import time
import requests
import smtplib
from datetime import datetime, timedelta, timezone
from collections import defaultdict
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
    PageBreak, HRFlowable, Image
)
from reportlab.lib.enums import TA_CENTER


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
REPORT_TYPE        = os.environ.get("REPORT_TYPE", "mensuel")


# =========================================================
# Helpers Loki
# =========================================================
def loki_instant_24h(expr: str, ts: int) -> list:
    """Requête Loki instant [24h] à un timestamp donné (nanosecondes)."""
    params = {"query": expr, "time": str(ts), "limit": "5000"}
    try:
        r = requests.get(f"{LOKI_URL}/loki/api/v1/query", params=params, timeout=120)
        if r.status_code != 200:
            print(f"  Loki {r.status_code} at ts={ts}: {r.text[:300]}")
            return []
        return r.json().get("data", {}).get("result", [])
    except Exception as e:
        print(f"  Loki error at ts={ts}: {e}")
        return []


def loki_query_chunked(expr_template: str, label_key: str = None) -> dict:
    """
    Découpe LOOKBACK_DAYS en tranches de 24h.
    Additionne les résultats de chaque tranche.
    expr_template doit contenir {window} → remplacé par [24h].
    """
    expr   = expr_template.replace("{window}", "[24h]")
    totals = defaultdict(int)
    now_s = int(time.time())

    for day in range(LOOKBACK_DAYS):
        ts      = now_s - day * 86400
        results = loki_instant_24h(expr, ts)

        for r in results:
            metric = r.get("metric", {})
            value  = r.get("value", [None, "0"])
            val    = int(float(value[1])) if value and len(value) > 1 else 0
            key    = metric.get(label_key, "total") if label_key else "total"
            totals[key] += val

    return dict(totals)



def loki_query_logs(expr: str, limit: int = 1000) -> list:
    """Fetch raw log entries over LOOKBACK_DAYS via query_range."""
    end   = int(time.time())
    start = end - LOOKBACK_DAYS * 86400
    params = {"query": expr, "start": str(start), "end": str(end),
              "limit": str(limit), "direction": "forward"}
    try:
        r = requests.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, timeout=120)
        if r.status_code != 200:
            print(f"  Loki logs error: {r.text[:200]}")
            return []
        entries = []
        for stream in r.json().get("data", {}).get("result", []):
            for ts, line in stream.get("values", []):
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries
    except Exception as e:
        print(f"  Loki logs error: {e}")
        return []

def fmt_bytes(n: int) -> str:
    if n >= 1_000_000_000: return f"{n/1_000_000_000:.1f} GB"
    if n >= 1_000_000:     return f"{n/1_000_000:.1f} MB"
    if n >= 1_000:         return f"{n/1_000:.1f} kB"
    return f"{n} B"


# =========================================================
# Collecte des données
# =========================================================
def collect_data() -> dict:
    print(f"Collecting data ({LOOKBACK_DAYS} days, chunked 24h)...")
    data = {}

    print("  - EntraID connexions...")
    data["entraid_success"] = loki_query_chunked(
        'sum(count_over_time({source="entra_id", filename=~"/logs/entra_signins_.*[.]jsonl"} | json | event_status_errorCode = "0" {window}))'
    ).get("total", 0)

    data["entraid_failures"] = loki_query_chunked(
        'sum(count_over_time({source="entra_id", filename=~"/logs/entra_signins_.*[.]jsonl"} | json | event_status_errorCode != "0" {window}))'
    ).get("total", 0)

    print("  - EntraID error codes...")
    data["entraid_error_codes"] = loki_query_chunked(
        'sum by (errorCode) (count_over_time({source="entra_id", filename=~"/logs/entra_signins_.*[.]jsonl"} | json errorCode="event.status.errorCode" | errorCode != "0" {window}))',
        label_key="errorCode"
    )

    print("  - EntraID top users...")
    data["entraid_top_users"] = loki_query_chunked(
        'sum by (upn) (count_over_time({source="entra_id", filename=~"/logs/entra_signins_.*[.]jsonl"} | json upn="event.userPrincipalName", errorCode="event.status.errorCode" | errorCode != "0" {window}))',
        label_key="upn"
    )

    print("  - EntraID foreign logins...")
    data["entraid_foreign"] = loki_query_chunked(
        'sum by (country) (count_over_time({source="entra_id"} | json country="event.location.countryOrRegion" | country != "FR" | country != "" {window}))',
        label_key="country"
    )

    print("  - AI volume...")
    data["ai_volume"] = loki_query_chunked(
        'sum by (app) (sum_over_time({job="fortigate"} |= "GenAI" | logfmt | unwrap sentbyte {window}))',
        label_key="app"
    )

    print("  - AI users...")
    data["ai_users"] = loki_query_chunked(
        'count by (app) (sum by (srcip, app) (count_over_time({job="fortigate"} |= "GenAI" | logfmt | srcip != "" | app != "" {window})))',
        label_key="app"
    )

    print("  - VPN activity...")
    for action, key in [
        ("ssl-new-con",    "vpn_success"),
        ("ssl-login-fail", "vpn_failures"),
        ("ssl-alert",      "vpn_ssl_alerts"),
    ]:
        data[key] = loki_query_chunked(
            f'sum(count_over_time({{job="fortigate"}} | logfmt | subtype="vpn" | action="{action}" {{window}}))'
        ).get("total", 0)

    print("  - FortiGate blocked services...")
    data["forti_blocked"] = loki_query_chunked(
        'sum by (service) (count_over_time({job="fortigate"} | logfmt | action="deny" | service != "" {window}))',
        label_key="service"
    )

    print("  - FortiGate critical events...")
    data["forti_critical"] = loki_query_chunked(
        'sum by (subtype) (count_over_time({job="fortigate"} | logfmt | level=~"alert|error" {window}))',
        label_key="subtype"
    )

    print("  - EntraID foreign login details...")
    data["entraid_foreign_details"] = loki_query_logs(
        '{source="entra_id"} | json country="event.location.countryOrRegion" | country != "FR" | country != ""'
    )

    # Connexions hors horaires (19h-05h heure France)
    # PAS de | json dans la query → Loki retourne les lignes brutes JSON
    # On parse en Python pour avoir accès aux champs imbriqués
    print("  - EntraID connexions hors horaires (19h-05h)...")
    all_signins = loki_query_logs(
        '{source="entra_id"}',
        limit=5000
    )
    off_hours = []
    for entry in all_signins:
        # entry = json.loads(ligne_brute)
        # Structure : {"labels":{...}, "event":{...}, "ingested_at":"..."}
        ev = entry.get("event", {})
        if not ev:
            continue
        dt_str = ev.get("createdDateTime", "")
        if not dt_str:
            continue
        try:
            dt_utc = datetime.strptime(dt_str[:16], "%Y-%m-%dT%H:%M")
            dt_fr  = dt_utc + timedelta(hours=1)  # UTC+1 hiver France
            h = dt_fr.hour
            if h >= 19 or h < 6:
                status     = ev.get("status", {})
                error_code = str(status.get("errorCode", "")) if isinstance(status, dict) else ""
                statut     = "Reussie" if error_code == "0" else f"Echec ({error_code})"
                loc        = ev.get("location", {})
                ville      = loc.get("city", "")             if isinstance(loc, dict) else ""
                pays       = loc.get("countryOrRegion", "")  if isinstance(loc, dict) else ""
                off_hours.append({
                    "dt_fr":       dt_fr.strftime("%d/%m/%Y %H:%M"),
                    "email":       ev.get("userPrincipalName", ""),
                    "nom":         ev.get("userDisplayName",   ""),
                    "ip":          ev.get("ipAddress",         ""),
                    "methode":     ev.get("appDisplayName",    ""),
                    "application": ev.get("clientAppUsed",     ""),
                    "statut":      statut,
                    "ville":       ville,
                    "pays":        pays,
                })
        except Exception as e:
            print(f"    off_hours parse error: {e}")
            continue
    data["entraid_off_hours"] = sorted(off_hours, key=lambda x: x["dt_fr"])
    print(f"    -> {len(off_hours)} connexions hors horaires trouvees")


    print("Collection complete.")
    return data


# =========================================================
# Génération PDF
# =========================================================

YMCA_GREEN = colors.HexColor("#95C11F")

def add_watermark(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 70)
    canvas.setFillColor(colors.HexColor("#95C11F"))
    canvas.setFillAlpha(0.15)
    canvas.translate(A4[0]/2, A4[1]/2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "CONFIDENTIEL")
    canvas.restoreState()

def build_pdf(data: dict, filepath: str, period_label: str) -> None:
    doc = SimpleDocTemplate(filepath, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    normal = styles["Normal"]

    title_s    = ParagraphStyle("t",  parent=styles["Title"],   fontSize=36, fontName="Helvetica-Bold", textColor=colors.HexColor("#95C11F"), alignment=TA_CENTER, spaceAfter=6)
    sub_s      = ParagraphStyle("s",  parent=normal,             fontSize=11, textColor=colors.HexColor("#555555"), alignment=TA_CENTER, spaceAfter=20)
    h1_s       = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=22, fontName="Helvetica-BoldOblique", textColor=colors.HexColor("#95C11F"), spaceBefore=20, spaceAfter=10)
    h2_s       = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#95C11F"), spaceBefore=12, spaceAfter=6)
    small_s    = ParagraphStyle("sm", parent=normal, fontSize=9, textColor=colors.HexColor("#666666"))
    footer_s   = ParagraphStyle("ft", parent=normal, fontSize=8, textColor=colors.HexColor("#999999"), alignment=TA_CENTER)

    HDR   = colors.HexColor("#002E10")
    ALT   = colors.HexColor("#f5f5f5")

    def tbl(headers, rows, widths=None):
        t = Table([headers] + rows, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0),  HDR),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, ALT]),
            ("GRID",           (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING",     (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
            ("LEFTPADDING",    (0,0), (-1,-1), 8),
        ]))
        return t

    def hr(): return HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"))
    def sp(n=0.3): return Spacer(1, n*cm)

    story = []

    # Page de garde
    import os as _os
    logo_path = "/app/ymca_logo.png"
    logo_els  = []
    if _os.path.exists(logo_path):
        logo = Image(logo_path, width=14*cm, height=9*cm)
        logo.hAlign = "CENTER"
        logo_els = [logo, sp(0.5)]
    story += [sp(1)] + logo_els + [sp(1), Paragraph("Sec-Stack YMCA", title_s),
              sp(0.5), Paragraph(f"Rapport de securite {REPORT_TYPE.capitalize()}", sub_s),
              Paragraph(f"Periode : {period_label}", sub_s),
              Paragraph(f"Genere le : {datetime.now().strftime('%d/%m/%Y a %H:%M')}", sub_s),
              sp(1), HRFlowable(width="100%", thickness=2, color=colors.HexColor("#002E10")), sp(0.5),
              Paragraph(f"Rapport {REPORT_TYPE} automatique de Sec-Stack", small_s),
              PageBreak()]

    # Calculs résumé
    total_auth = data["entraid_success"] + data["entraid_failures"]
    fail_rate  = (data["entraid_failures"] / total_auth * 100) if total_auth > 0 else 0
    lockouts   = data["entraid_error_codes"].get("50053", 0)
    FailLogOn = data["entraid_error_codes"].get("50126", 0)
    total_ai   = sum(data["ai_volume"].values())
    foreign    = sum(data["entraid_foreign"].values())

    # Section 1 — Résumé
    story += [Paragraph("1. Resume executif", h1_s), hr(), sp()]
    story.append(tbl(
        ["Indicateur", "Valeur", "Interpretation"],
        [
            ["Connexions Entra ID reussies",   str(data["entraid_success"]),  ""],
            ["Connexions Entra ID echouees",   str(data["entraid_failures"]), f"{fail_rate:.1f}% du total"],
            ["Comptes verouilles (50053)",     str(lockouts),    "A verifier" if lockouts > 0 else "OK"],
            ["identifiants invalides (50126)",            str(FailLogOn),  "Surveiller" if FailLogOn > 30 else "Normal"],
            ["Connexions depuis l'etranger",   str(foreign),     "A qualifier" if foreign > 0 else "Aucune"],
            ["Volume total vers services IA",  fmt_bytes(total_ai), ""],
            ["Tunnels VPN etablis",            str(data["vpn_success"]),  ""],
            ["Echecs login VPN",               str(data["vpn_failures"]), "Surveiller" if data["vpn_failures"] > 10 else "Normal"],
        ],
        widths=[9*cm, 3*cm, 5.5*cm]
    ))
    story.append(PageBreak())

    # Section 2 — EntraID
    story += [Paragraph("2. Alertes critiques Entra ID", h1_s), hr(), sp(),
              Paragraph("2.1 Top codes d'erreur", h2_s)]

    ERROR_LABELS = {
        "50126":"Identifiants invalides","50125":"Echec auth","50053":"Compte verouille",
        "50055":"MDP expire","50057":"Compte desactive","50074":"MFA requis",
        "50072":"MFA / interaction","70044":"Token expire","9002341":"SSO a autoriser",
    }
    error_rows = sorted(data["entraid_error_codes"].items(), key=lambda x: x[1], reverse=True)
    if error_rows:
        story.append(tbl(["Code", "Description", "Occurrences"],
            [[c, ERROR_LABELS.get(c,"Autre"), str(v)] for c,v in error_rows[:10]],
            widths=[3*cm, 10*cm, 4.5*cm]))
    else:
        story.append(Paragraph("Aucune erreur detectee.", normal))

    story += [sp(), Paragraph("2.2 Top utilisateurs (echecs auth)", h2_s)]
    user_rows = sorted(data["entraid_top_users"].items(), key=lambda x: x[1], reverse=True)
    if user_rows:
        story.append(tbl(["Utilisateur","Echecs"],
            [[u, str(v)] for u,v in user_rows[:10]], widths=[13*cm, 4.5*cm]))
    else:
        story.append(Paragraph("Aucun echec significatif.", normal))
    story.append(PageBreak())

    # Section 3 — Connexions étrangères
    story += [Paragraph("3. Connexions depuis l'etranger", h1_s), hr(), sp()]
    if data["entraid_foreign"]:
        story.append(tbl(["Pays","Connexions"],
            [[c, str(v)] for c,v in sorted(data["entraid_foreign"].items(), key=lambda x: x[1], reverse=True)],
            widths=[13*cm, 4.5*cm]))
        story += [sp(), Paragraph("Une connexion etrangere peut etre legitime (VPN, deplacement) ou indiquer une compromission. A qualifier.", small_s)]
    else:
        story.append(Paragraph("Aucune connexion etrangere detectee.", normal))
    # Tableau détaillé des tentatives étrangères
    if data.get("entraid_foreign_details"):
        story += [sp(), Paragraph("3.1 Detail des tentatives", h2_s)]
        detail_rows = []
        for entry in data["entraid_foreign_details"]:
            ev = entry.get("event", {})
            status = ev.get("status", {})
            error  = status.get("errorCode", "")
            locked = "OUI" if str(error) == "50053" else ""
            result = "Reussie" if str(error) == "0" else "Echec"
            detail_rows.append([
                ev.get("createdDateTime", "")[:16].replace("T", " "),
                ev.get("userDisplayName", ev.get("userPrincipalName", "")),
                ev.get("ipAddress", ""),
                ev.get("location", {}).get("countryOrRegion", ""),
                result,
                locked,
            ])
        detail_rows.sort(key=lambda x: x[0])
        story.append(tbl(
            ["Date/Heure (UTC)", "Utilisateur", "IP Source", "Pays", "Resultat", "Verrouille"],
            detail_rows,
            widths=[3.5*cm, 5*cm, 3.5*cm, 1.5*cm, 2*cm, 2*cm]
        ))

    story.append(PageBreak())

    # Section 3.2 — Connexions hors horaires
    story += [Paragraph("3.2 Connexions hors horaires (19h - 05h)", h1_s), hr(), sp(),
              Paragraph(
                  "Connexions enregistrees entre 19h00 et 05h59 (heure France). "
                  "Ces evenements peuvent indiquer un acces non autorise, un compte compromis "
                  "ou un usage en dehors des heures ouvrables.",
                  small_s
              ), sp()]

    off_hours_rows = []
    for entry in data.get("entraid_off_hours", []):
        ev     = entry.get("event", {})
        status = ev.get("status", {})
        error  = str(status.get("errorCode", ""))
        result = "Reussie" if error == "0" else f"Echec ({error})"
        dt_utc = ev.get("createdDateTime", "")[:16].replace("T", " ")
        # Convertir UTC -> heure France approximative (+1h hiver, +2h ete)
        try:
            dt_obj   = datetime.strptime(dt_utc, "%Y-%m-%d %H:%M")
            dt_local = dt_obj + timedelta(hours=1)
            dt_fr    = dt_local.strftime("%d/%m/%Y %H:%M")
        except Exception:
            dt_fr = dt_utc
        loc = ev.get("location", {})
        ville = f"{loc.get('city','')}, {loc.get('countryOrRegion','')}" if loc else ""
        off_hours_rows.append([
            dt_fr,
            ev.get("userDisplayName", ev.get("userPrincipalName", "")),
            ev.get("userPrincipalName", ""),
            ev.get("appDisplayName", ""),
            ev.get("clientAppUsed", ""),
            ev.get("ipAddress", ""),
            result,
            ville,
        ])

    off_hours_rows.sort(key=lambda x: x[0])

    if off_hours_rows:
        story.append(Paragraph(f"{len(off_hours_rows)} evenement(s) detecte(s).", normal))
        story.append(sp(0.2))
        story.append(tbl(
            ["Date/Heure (FR)", "Nom", "Utilisateur", "Application", "Client", "IP", "Statut", "Localisation"],
            off_hours_rows,
            widths=[2.8*cm, 2.5*cm, 3.5*cm, 2.5*cm, 2*cm, 2.5*cm, 2*cm, 2.5*cm]
        ))
        story += [sp(), Paragraph(
            "Les connexions hors horaires reussies meritent d'etre qualifiees. "
            "Un compte presentant plusieurs echecs nocturnes peut indiquer une tentative de brute force.",
            small_s
        )]
    else:
        story.append(Paragraph("Aucune connexion hors horaires detectee sur la periode.", normal))

    story.append(PageBreak())

    # Section 4 — IA
    story += [Paragraph("4. Consommation des services IA", h1_s), hr(), sp()]
    all_apps = set(list(data["ai_volume"].keys()) + list(data["ai_users"].keys()))
    if all_apps:
        ai_rows = sorted([[a, fmt_bytes(data["ai_volume"].get(a,0)), str(data["ai_users"].get(a,0))] for a in all_apps],
                          key=lambda x: data["ai_volume"].get(x[0],0), reverse=True)
        story.append(tbl(["Service IA","Volume envoye","Postes distincts"], ai_rows, widths=[7*cm,6*cm,4.5*cm]))
        story += [sp(), Paragraph(f"Volume total : {fmt_bytes(total_ai)}", normal), sp(0.2),
                  Paragraph("Un volume eleve peut indiquer une fuite de donnees sensibles. A croiser avec la politique IA.", small_s)]
    else:
        story.append(Paragraph("Aucune consommation IA detectee.", normal))
    story.append(PageBreak())

    # Section 5 — VPN
    story += [Paragraph("5. Activite VPN SSL", h1_s), hr(), sp()]
    story.append(tbl(["Evenement","Occurrences","Interpretation"], [
        ["Tunnels etablis (ssl-new-con)",      str(data["vpn_success"]),    "Connexions legitimes"],
        ["Echecs login (ssl-login-fail)",       str(data["vpn_failures"]),   "Surveiller" if data["vpn_failures"]>10 else "Normal"],
        ["Erreurs SSL (ssl-alert/exit-error)", str(data["vpn_ssl_alerts"]), "Bruit de fond (scanners)"],
    ], widths=[7*cm, 3.5*cm, 7*cm]))
    story += [sp(), Paragraph("Les erreurs SSL sont du bruit de fond internet. Les echecs login meritent investigation.", small_s)]
    story.append(PageBreak())

    # Section 6 — FortiGate
    story += [Paragraph("6. Top services bloques FortiGate", h1_s), hr(), sp()]
    if data["forti_blocked"]:
        story.append(tbl(["Service / Application","Blocages"],
            [[s, str(v)] for s,v in sorted(data["forti_blocked"].items(), key=lambda x: x[1], reverse=True)[:10]],
            widths=[13*cm, 4.5*cm]))
    else:
        story.append(Paragraph("Aucun service bloque detecte.", normal))

    story += [sp(), Paragraph("6.1 Evenements critiques (level=alert/error)", h2_s)]
    if data["forti_critical"]:
        story.append(tbl(["Sous-type","Occurrences"],
            [[s, str(v)] for s,v in sorted(data["forti_critical"].items(), key=lambda x: x[1], reverse=True)],
            widths=[13*cm, 4.5*cm]))
    else:
        story.append(Paragraph("Aucun evenement critique detecte.", normal))

    # Pied de page
    story += [sp(1), HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")), sp(0.2),
              Paragraph(f"Rapport {REPORT_TYPE} automatique de Sec-Stack - {datetime.now().strftime('%d/%m/%Y')}", footer_s)]

    doc.build(story, onFirstPage=add_watermark, onLaterPages=add_watermark)
    print(f"PDF generated: {filepath}")


# =========================================================
# Envoi email
# =========================================================
def send_email(pdf_path: str, period_label: str) -> None:
    msg = MIMEMultipart()
    msg["From"]    = REPORT_FROM
    msg["To"]      = REPORT_TO
    msg["Subject"] = f"[SOC-Mini YMCA] Rapport {REPORT_TYPE} - {period_label}"
    msg.attach(MIMEText(
        f"Bonjour,\n\nVeuillez trouver en piece jointe le rapport {REPORT_TYPE} SOC-Mini YMCA "
        f"pour la periode : {period_label}.\n\nCordialement,\nSOC-Mini YMCA", "plain"))

    with open(pdf_path, "rb") as f:
        att = MIMEBase("application", "octet-stream")
        att.set_payload(f.read())
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", f"attachment; filename={os.path.basename(pdf_path)}")
        msg.attach(att)

    with smtplib.SMTP("in-v3.mailjet.com", 587) as s:
        s.ehlo(); s.starttls()
        s.login(MAILJET_API_KEY, MAILJET_SECRET_KEY)
        s.sendmail(REPORT_FROM, REPORT_TO, msg.as_string())

    print(f"Email sent to {REPORT_TO}")


# =========================================================
# Main
# =========================================================
def main() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    now          = datetime.now(timezone.utc)
    last_month   = now - timedelta(days=LOOKBACK_DAYS)
    period_label = f"{last_month.strftime('%d/%m/%Y')} - {now.strftime('%d/%m/%Y')}"
    filename     = f"soc-report-{REPORT_TYPE}-{now.strftime('%Y-%m-%d')}.pdf"
    filepath     = os.path.join(REPORT_DIR, filename)

    print("=== SOC-Mini Report Generator ===")
    print(f"Period : {period_label}")
    print(f"Chunks : {LOOKBACK_DAYS} x 24h")
    print(f"Output : {filepath}")

    data = collect_data()
    build_pdf(data, filepath, period_label)
    send_email(filepath, period_label)
    print("=== Report done ===")


if __name__ == "__main__":
    main()
