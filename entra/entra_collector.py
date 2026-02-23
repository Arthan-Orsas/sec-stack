"""
entra_collector.py — Collecte des logs Microsoft Entra ID via Microsoft Graph (mode application)

Objectif
--------
Ce script récupère périodiquement des événements Entra ID via Microsoft Graph, puis les écrit
dans des fichiers JSON Lines (.jsonl) que Promtail “tail” et pousse dans Loki → Grafana.

Endpoints collectés :
- auditLogs/signIns           (connexions / authentifications)
- auditLogs/directoryAudits   (audits annuaire)

Pourquoi JSON Lines (.jsonl) ?
------------------------------
- 1 événement JSON par ligne → facile à streamer (Promtail)
- append simple, debug simple
- pas besoin de base de données lourde

Problèmes classiques rencontrés (et solutions ici)
--------------------------------------------------
1) Doublons dans Grafana (ex: un utilisateur “a 70 échecs” alors qu’il a fait 1 faute)
   Cause : LOOKBACK + relance conteneur + Promtail relit + le script réécrit les mêmes events.
   Solution : DÉDUPLICATION par event.id (persistante) avant d’écrire dans les fichiers.

2) 429 Too Many Requests sur directoryAudits
   Cause : Graph throttle très vite si tu pagines agressivement.
   Solution : on limite à 1 page ($top=N) + backoff (Retry-After / exponentiel).

3) 400 Bad Request sur les filtres datetime
   Cause fréquente : microsecondes ou format strict.
   Solution : on formate les dates en ISO UTC SANS microsecondes.

4) Rétention 3 mois “comme un anneau”
   Ce que tu décris (“le 01/04 réécrit sur le 01/01”) = un système de stockage circulaire.
   Sur des fichiers, on ne réécrit pas “sur” un ancien fichier : on supprime les vieux fichiers.
   Le résultat fonctionnel est le même : tu gardes toujours les 90 derniers jours.
   Solution : rotation quotidienne + suppression des fichiers plus vieux que RETENTION_DAYS.

Variables d’environnement
-------------------------
Obligatoires :
- TENANT_ID
- CLIENT_ID
- CLIENT_SECRET

Optionnelles :
- LOG_DIR=/logs
- STATE_DIR=/state
- POLL_SECONDS=300
- LOOKBACK_MINUTES=10
- DIRECTORY_AUDITS_TOP=50
- RETENTION_DAYS=90

Notes importantes
-----------------
- Promtail lit /logs/*.jsonl : donc on peut créer un fichier par jour, ça reste compatible.
- Les KPI Grafana doivent se baser sur des logs SANS doublons. Ici, on déduplique sur event.id.
"""

import os
import re
import json
import time
import sqlite3
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional


# =========================================================
# Paramètres (Docker / Synology)
# =========================================================
TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

LOG_DIR = os.environ.get("LOG_DIR", "/logs")
STATE_DIR = os.environ.get("STATE_DIR", "/state")

POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "300"))          # 5 min
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "10"))   # anti-trous
DIRECTORY_AUDITS_TOP = int(os.environ.get("DIRECTORY_AUDITS_TOP", "50"))

# Rétention fichier (3 mois ≈ 90 jours)
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "90"))

# OAuth2 token endpoint (v2.0)
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# Scope Graph :
# ".default" = utilise les permissions Application attribuées à l'app
SCOPE = "https://graph.microsoft.com/.default"

ENDPOINTS = {
    "signins": "https://graph.microsoft.com/v1.0/auditLogs/signIns",
    "directory_audits": "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
}


# =========================================================
# Helpers temps
# =========================================================
def iso_utc_now_no_us() -> str:
    """
    Retourne UTC now au format ISO 8601 SANS microsecondes.
    Exemple : 2026-01-29T11:22:22Z
    """
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def iso_utc_minutes_ago_no_us(minutes: int) -> str:
    """
    Retourne UTC (now - minutes) en ISO 8601 sans microsecondes.
    Sert pour “since” dans les checkpoints.
    """
    return (
        (datetime.now(timezone.utc) - timedelta(minutes=minutes))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def today_utc_yyyymmdd() -> str:
    """
    Sert à la rotation de fichiers par jour (UTC, stable côté serveur).
    Exemple : 20260129
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d")


# =========================================================
# OAuth2 client_credentials (token)
# =========================================================
def get_token() -> str:
    """
    Récupère un access token via OAuth2 client_credentials.

    Si tu obtiens :
    - AADSTS7000215 invalid_client : tu as mis l’ID du secret au lieu de la VALUE
    - 401 unauthorized : secret expiré / mauvais tenant / mauvais client id
    """
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": SCOPE,
        "grant_type": "client_credentials",
    }
    r = requests.post(TOKEN_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


# =========================================================
# Checkpoints (since) — état par endpoint
# =========================================================
def checkpoint_path(name: str) -> str:
    return os.path.join(STATE_DIR, f"{name}.checkpoint")


def read_checkpoint(name: str) -> str:
    """
    - Si checkpoint absent : première exécution → “now - LOOKBACK”
    - Sinon : on lit l’ISO stocké
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    path = checkpoint_path(name)

    if not os.path.exists(path):
        return iso_utc_minutes_ago_no_us(LOOKBACK_MINUTES)

    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def write_checkpoint(name: str, value: str) -> None:
    """
    On écrit un ISO “propre” dans /state/<name>.checkpoint
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    path = checkpoint_path(name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(value)


# =========================================================
# Déduplication persistante (SQLite) — cœur de la fiabilité KPI
# =========================================================
def dedup_db_path() -> str:
    return os.path.join(STATE_DIR, "dedup.db")


def dedup_db_init() -> None:
    """
    On utilise SQLite car :
    - inclus par défaut
    - persistant (volume /state)
    - rapide
    - simple

    Table “seen” :
    - event_id : identifiant unique Graph (event.id)
    - seen_at  : timestamp epoch (pour purge)
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(dedup_db_path())
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS seen (
              event_id TEXT PRIMARY KEY,
              seen_at  INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def dedup_is_new(event_id: str) -> bool:
    """
    Retourne True si event_id jamais vu, sinon False.
    - On insert en base : si ça échoue (clé déjà existante) → déjà vu.
    """
    now_epoch = int(time.time())
    conn = sqlite3.connect(dedup_db_path())
    try:
        try:
            conn.execute(
                "INSERT INTO seen(event_id, seen_at) VALUES(?, ?)",
                (event_id, now_epoch),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # event_id déjà présent
            return False
    finally:
        conn.close()


def dedup_purge_older_than(days: int) -> None:
    """
    Purge la table dedup pour éviter qu’elle grossisse indéfiniment.
    On garde les IDs “vus” sur la même période que la rétention.
    """
    cutoff_epoch = int(time.time()) - (days * 86400)
    conn = sqlite3.connect(dedup_db_path())
    try:
        conn.execute("DELETE FROM seen WHERE seen_at < ?", (cutoff_epoch,))
        conn.commit()
    finally:
        conn.close()


# =========================================================
# Écriture JSONL + rotation quotidienne + rétention
# =========================================================
def daily_filename(base_name: str) -> str:
    """
    Crée un nom du type :
    entra_signins_YYYYMMDD.jsonl
    entra_directory_audits_YYYYMMDD.jsonl
    """
    return f"{base_name}_{today_utc_yyyymmdd()}.jsonl"


def append_jsonl_deduped(filename: str, records: List[dict], labels: Dict[str, str]) -> Tuple[int, int]:
    """
    Écrit des événements en JSONL en DÉDUPLIQUANT par event.id.

    Retourne (written, skipped_duplicates)

    Structure d’une ligne :
    {
      "labels": {...},
      "event":  {...},         # payload Graph brut
      "ingested_at": "..."     # ISO UTC ingestion
    }

    Point important :
    - On ne fait PAS confiance à Promtail pour dédupliquer.
    - On déduplique à la source, sinon les KPI deviennent faux.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, filename)

    written = 0
    skipped = 0

    with open(path, "a", encoding="utf-8") as f:
        for rec in records:
            event_id = rec.get("id")
            if not event_id:
                # Rare, mais si pas d'id, on écrit quand même (sinon perte de logs)
                event_id = None

            # Si on a un ID, on déduplique
            if event_id:
                if not dedup_is_new(event_id):
                    skipped += 1
                    continue

            out = {
                "labels": labels,
                "event": rec,
                "ingested_at": iso_utc_now_no_us(),
            }
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
            written += 1

    return written, skipped


def retention_cleanup_logs(days: int) -> None:
    """
    Supprime les fichiers .jsonl plus vieux que <days> dans LOG_DIR.

    Comme on fait une rotation quotidienne (YYYYMMDD), c’est simple :
    - on détecte les fichiers qui ont un suffixe _YYYYMMDD.jsonl
    - si date < aujourd’hui - days → suppression
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    cutoff_date = datetime.now(timezone.utc).date() - timedelta(days=days)
    pattern = re.compile(r".*_(\d{8})\.jsonl$")

    for name in os.listdir(LOG_DIR):
        if not name.endswith(".jsonl"):
            continue

        m = pattern.match(name)
        if not m:
            # Si le fichier ne suit pas le pattern, on peut ignorer (ou gérer au mtime).
            continue

        yyyymmdd = m.group(1)
        try:
            file_date = datetime.strptime(yyyymmdd, "%Y%m%d").date()
        except ValueError:
            continue

        if file_date < cutoff_date:
            try:
                os.remove(os.path.join(LOG_DIR, name))
                print(f"retention: deleted old log file: {name}")
            except Exception as e:
                print(f"retention: WARNING cannot delete {name}: {e}")


# =========================================================
# Graph helpers : pagination et throttling
# =========================================================
def fetch_paged(url: str, headers: dict) -> List[dict]:
    """
    Déroule toutes les pages Graph via @odata.nextLink.
    OK pour signIns en général.

    Si Graph renvoie 429 ici, ça remonte comme exception :
    - dans ce script, on ne s’en sert pas pour directoryAudits.
    """
    all_items: List[dict] = []
    next_url: Optional[str] = url

    while next_url:
        r = requests.get(next_url, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()

        all_items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")

    return all_items


def get_with_backoff(url: str, headers: dict, timeout: int = 60, max_retries: int = 5) -> dict:
    """
    GET Graph avec gestion des 429.

    - Retry-After si fourni
    - sinon backoff exponentiel : 2^attempt (plafonné à 60s)
    """
    for attempt in range(1, max_retries + 1):
        r = requests.get(url, headers=headers, timeout=timeout)

        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                wait_s = int(retry_after)
            else:
                wait_s = min(2 ** attempt, 60)

            print(f"THROTTLED 429 -> waiting {wait_s}s (attempt {attempt}/{max_retries})")
            time.sleep(wait_s)
            continue

        r.raise_for_status()
        return r.json()

    raise RuntimeError(f"Graph throttling persists after {max_retries} retries (url={url})")


def build_filter_url_created_ge(base: str, since_iso: str) -> str:
    """
    Construit un filtre OData : createdDateTime ge <ISO>

    NB :
    - Le since_iso est sans microsecondes (important).
    - Les espaces seront encodés (%20) par requests si besoin.
    """
    return f"{base}?$filter=createdDateTime ge {since_iso}"


# =========================================================
# Cycle de collecte
# =========================================================
def run_once() -> None:
    """
    Exécute un cycle complet :
    1) Token
    2) Sign-ins (filtré + pagination)
    3) Directory audits (1 page + backoff 429)
    4) Maintenance :
       - purge dedup.db (même fenêtre que rétention)
       - nettoyage vieux fichiers logs
    """
    # --- Préparation dedup (au cas où c’est le premier run) ---
    dedup_db_init()

    # --- Token OAuth2 ---
    token = get_token()

    # Bonnes pratiques :
    # - User-Agent custom → debug et traçabilité côté Microsoft
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "ymca-entra-collector/1.0",
    }

    # =======================================================
    # 1) SIGN-INS
    # =======================================================
    # Ici le checkpoint pilote VRAIMENT l’appel Graph, donc on limite les relectures.
    # LOOKBACK ajoute un petit recouvrement → possible doublon MAIS on déduplique par id.
    since = read_checkpoint("signins")
    url = build_filter_url_created_ge(ENDPOINTS["signins"], since)

    signins = fetch_paged(url, headers)

    # Rotation journalière : fichier du jour
    signins_file = daily_filename("entra_signins")

    written, skipped = append_jsonl_deduped(
        signins_file,
        signins,
        {"source": "entra_id", "type": "signins"},
    )

    # On avance le checkpoint à “now - LOOKBACK”
    # (ce qui garde la propriété anti-trou)
    write_checkpoint("signins", iso_utc_minutes_ago_no_us(LOOKBACK_MINUTES))

    print(
        f"signins: api_received={len(signins)} "
        f"written={written} skipped_duplicates={skipped} since={since} file={signins_file}"
    )

    # =======================================================
    # 2) DIRECTORY AUDITS
    # =======================================================
    # Contrairement aux sign-ins :
    # - directoryAudits throttle vite (429)
    # - la pagination peut empirer le throttling
    #
    # Stratégie SOC light :
    # - 1 page ($top=N)
    # - backoff sur 429
    # - déduplication par id
    last_checkpoint = read_checkpoint("directory_audits")  # traçabilité uniquement

    # On récupère “les derniers N”
    # (si tu veux : on peut essayer $orderby=activityDateTime desc, mais on reste minimal ici)
    url = ENDPOINTS["directory_audits"] + f"?$top={DIRECTORY_AUDITS_TOP}"

    audits_file = daily_filename("entra_directory_audits")

    try:
        data = get_with_backoff(url, headers, timeout=60, max_retries=5)
        audits = data.get("value", [])

        w2, s2 = append_jsonl_deduped(
            audits_file,
            audits,
            {"source": "entra_id", "type": "directory_audits"},
        )

        # Checkpoint conservé comme “dernier run” (pas utilisé comme filtre)
        write_checkpoint("directory_audits", iso_utc_minutes_ago_no_us(LOOKBACK_MINUTES))

        print(
            f"directory_audits: api_received={len(audits)} "
            f"written={w2} skipped_duplicates={s2} "
            f"(1 page, throttling-safe) last_checkpoint_was={last_checkpoint} file={audits_file}"
        )

    except Exception as e:
        # On ne casse pas tout le cycle si directoryAudits est capricieux.
        print(f"WARNING directory_audits collection failed (continuing): {e}")

    # =======================================================
    # 3) Maintenance (à chaque cycle, léger)
    # =======================================================
    # - purge dedup : sinon la base grossit
    # - rétention fichiers : sinon /logs gonfle
    dedup_purge_older_than(RETENTION_DAYS)
    retention_cleanup_logs(RETENTION_DAYS)


def main() -> None:
    """
    Boucle infinie :
    - run_once()
    - sleep(POLL_SECONDS)

    On catch les exceptions globales pour éviter que le conteneur s’arrête.
    """
    print("Entra collector started")

    while True:
        try:
            run_once()
            print("Collected Entra logs OK")
        except Exception as e:
            print(f"ERROR collecting Entra logs: {e}")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
