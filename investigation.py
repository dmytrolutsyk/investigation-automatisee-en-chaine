"""Investigation chaînée automatisée de logs de sécurité Windows.

Usage :
    python3 investigation.py [chemin_logs.json] [--enrichir]

Le chemin des logs surcharge FICHIER_LOGS ; --enrichir active VirusTotal.

Étapes (chaque conclusion alimente la suivante) :
    1. détection des IP à échecs d'authentification (4625) en rafale ;
    2. recherche des connexions réussies (4624) depuis ces IP ;
    3. activité post-compromission des comptes touchés ;
    4. rebond latéral via les comptes créés ou les nouvelles connexions.
Sorties : rapport texte, PDF, export MISP (CSV) et STIX (JSON).
Les heures sont affichées en UTC.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json

# --- Paramètres -------------------------------------------------------------
FICHIER_LOGS = "logs_test.json"
SEUIL_ECHECS = 10          # échecs minimum depuis une IP pour la signaler
SEUIL_COMPTES = 5          # comptes distincts minimum pour parler de spray
RESEAUX_INTERNES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Codes d'événements Windows
EVT_ECHEC = 4625
EVT_SUCCES = 4624
EVT_PROCESSUS = 4688
EVT_TACHE = 4698
EVT_CREATION_COMPTE = 4720
EVT_AJOUT_GROUPE = 4732
EVT_EFFACEMENT = 1102

PARENTS_BUREAUTIQUES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                        "msaccess.exe", "mspub.exe", "onenote.exe"}
INTERPRETEURS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                 "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
MARQUEURS_CMD_SUSPECTS = ("-enc", "-encodedcommand", "-nop", "hidden",
                          "downloadstring", "iex")
# Comparaison en minuscules
GROUPES_PRIVILEGIES = {"administrateurs", "administrators", "admins du domaine",
                       "domain admins", "administrateurs de l'entreprise",
                       "enterprise admins", "utilisateurs du bureau à distance",
                       "remote desktop users"}

# Chemins de sortie
SORTIE_TXT = "sortie_rapport.txt"
SORTIE_PDF = "rapport_incident.pdf"
SORTIE_MISP = "iocs_misp.csv"
SORTIE_STIX = "iocs_stix.json"

# VirusTotal
VT_CACHE = "cache_vt.json"
VT_TTL_HEURES = 24
VT_INTERVALLE_S = 15
VT_TIMEOUT_S = 10
VT_MAX_ESSAIS = 3


# --- Modèle et chargement ---------------------------------------------------
@dataclass(frozen=True)
class Evenement:
    """Un événement de journal normalisé."""
    timestamp: datetime
    event_id: int
    host: str
    account: str
    src_ip: str | None
    logon_type: int | None
    result: str
    details: dict


class ErreurChargement(Exception):
    """Le fichier de logs est absent, illisible ou de structure invalide."""


def parse_ts(texte: str) -> datetime:
    """Convertit un horodatage ISO 8601 (Z, +00:00, fractions) en datetime UTC aware."""
    dt = datetime.fromisoformat(texte.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _entier(valeur, defaut):
    """Entier ou valeur par défaut si la conversion est impossible."""
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return defaut


def charger_logs(chemin: str) -> list[Evenement]:
    """Charge le fichier JSON de logs et renvoie les événements triés par date.

    Les événements sans horodatage exploitable sont ignorés ; les champs
    absents reçoivent une valeur par défaut.
    """
    try:
        with open(chemin, encoding="utf-8") as f:
            brut = json.load(f)
    except FileNotFoundError:
        raise ErreurChargement(f"Fichier de logs introuvable : {chemin}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ErreurChargement(f"Lecture impossible de {chemin} : {exc}") from None
    except json.JSONDecodeError as exc:
        raise ErreurChargement(f"JSON invalide dans {chemin} : {exc}") from None
    if not isinstance(brut, list):
        raise ErreurChargement(
            f"Format inattendu dans {chemin} : une liste d'événements est attendue")

    evenements = []
    for obj in brut:
        if not isinstance(obj, dict):
            continue
        try:
            ts = parse_ts(obj["timestamp"])
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        details = obj.get("details")
        evenements.append(Evenement(
            timestamp=ts,
            event_id=_entier(obj.get("event_id"), 0),
            host=obj.get("host") or "",
            account=obj.get("account") or "",
            src_ip=obj.get("src_ip") or None,
            logon_type=_entier(obj.get("logon_type"), None),
            result=obj.get("result") or "",
            details=details if isinstance(details, dict) else {},
        ))
    evenements.sort(key=lambda e: e.timestamp)
    return evenements
