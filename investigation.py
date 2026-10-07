"""Investigation chaînée automatisée de logs de sécurité Windows (exercice ForCERT).

But : partir d'un fichier JSON de journaux Windows et reconstituer un incident
de bout en bout, chaque étape s'appuyant sur les conclusions de la précédente :
    1. détection : IP à rafales d'échecs de connexion (4625), classées en
       password spraying, force brute ou faux positif interne ;
    2. pivot : connexions réussies (4624) depuis ces IP, donc comptes et
       machines compromis ;
    3. chronologie : activité après l'intrusion sur la machine compromise et
       par les comptes suivis (compte compromis, comptes créés par l'attaquant) ;
    4. plan d'action et gravité : chaque mesure est rattachée au fait observé ;
    5. IOC : extraction, enrichissement VirusTotal optionnel, exports MISP/STIX.

Usage :
    python3 investigation.py [logs.json] [--enrichir] [--pdf]
    (défaut : FICHIER_LOGS ; --enrichir interroge VirusTotal, clé dans VT_API_KEY ;
    --pdf produit en plus le rapport PDF)

Sorties (dossier courant) : rapport texte (affiché et sortie_rapport.txt),
rapport_incident.docx (Word, python-docx ; rapport_incident.pdf en plus avec --pdf,
reportlab), iocs_misp.csv (MISP) et iocs_stix.json (STIX 2.1).
Toutes les heures sont en UTC. Python 3.11 ou plus récent.

Paramètres : seuils, réseaux internes, marqueurs de commandes suspectes,
fichiers de sortie et réglages VirusTotal sont regroupés juste en dessous,
dans la section « Paramètres ».
"""
from __future__ import annotations

import argparse
import base64
import binascii
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import ntpath
import os
import re
import sys

from enrichissement_vt import ClientVT, enrichir_iocs
from iocs import exporter_misp_csv, exporter_stix, extraire_iocs

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
# Mots entiers suspects dans les arguments d'une commande (comparaison en minuscules)
MARQUEURS_CMD_SUSPECTS = ("hidden", "downloadstring", "iex", "bypass")
# Options PowerShell : tout préfixe non ambigu est accepté (-e, -enc, /enc...)
OPTION_ENCODEE = "-encodedcommand"        # dès 2 caractères (-e), plus l'alias -ec
OPTION_SANS_PROFIL = "-noprofile"         # dès 4 caractères (-nop) ; -nopause n'en est pas un
EXECUTABLES_POWERSHELL = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
# Types de connexion locaux (interactive, service, déverrouillage, interactive en
# cache) : sur une autre machine, à vérifier plutôt que mouvement latéral
TYPES_CONNEXION_LOCALE = {2, 5, 7, 11}
# Comparaison en minuscules
GROUPES_PRIVILEGIES = {"administrateurs", "administrators", "admins du domaine",
                       "domain admins", "administrateurs de l'entreprise",
                       "enterprise admins", "utilisateurs du bureau à distance",
                       "remote desktop users"}

# Chemins de sortie
SORTIE_TXT = "sortie_rapport.txt"
SORTIE_PDF = "rapport_incident.pdf"
SORTIE_DOCX = "rapport_incident.docx"
LOGO = "Logo.png"   # relatif au dossier du script ; absent : page de garde sans logo
SORTIE_MISP = "iocs_misp.csv"
SORTIE_STIX = "iocs_stix.json"

# VirusTotal
VT_CACHE = None     # None : interrogation en direct à chaque exécution (aucun fichier) ;
                    # mettre un chemin (ex. "cache_vt.json") pour garder les réponses
VT_TTL_HEURES = 24  # durée de validité du cache disque, s'il est activé
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


def _cle(texte) -> str:
    """Clé de comparaison d'un nom Windows (compte, machine) : insensible à la casse.

    On compare et regroupe sur cette clé, mais on affiche la première graphie vue.
    """
    return (texte or "").casefold()


def _dans(nom, noms) -> bool:
    """nom figure-t-il dans noms, sans tenir compte de la casse ?"""
    return _cle(nom) in {_cle(n) for n in noms}


def _premieres_graphies(noms) -> list[str]:
    """Noms distincts sans tenir compte de la casse (première graphie gardée), triés."""
    vus = {}
    for n in noms:
        vus.setdefault(_cle(n), n)
    return sorted(vus.values())


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


def _ip_source(valeur) -> str | None:
    """IP source normalisée ; vide, blanc ou « - » (IP nulle de Windows) donnent None."""
    if valeur is None:
        return None
    texte = str(valeur).strip()
    return None if texte in ("", "-") else texte


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
            src_ip=_ip_source(obj.get("src_ip")),
            logon_type=_entier(obj.get("logon_type"), None),
            result=obj.get("result") or "",
            details=details if isinstance(details, dict) else {},
        ))
    evenements.sort(key=lambda e: e.timestamp)
    return evenements


# --- Étape 1 : détection ----------------------------------------------------
@dataclass
class ProfilIP:
    """Profil d'échecs d'authentification d'une IP source."""
    ip: str
    nb_echecs: int
    comptes: list[str]
    hosts: list[str]
    debut: datetime
    fin: datetime
    categorie: str  # spraying | force_brute | faux_positif_probable | sous_seuil
    motif: str


@dataclass
class ResultatDetection:
    suspectes: list[ProfilIP]   # triées par début d'activité
    ecartees: list[ProfilIP]    # non suspectes, mais au-dessus du seuil d'échecs
    nb_echecs_total: int
    nb_ip_analysees: int
    nb_incoherences_result: int  # 4625 dont le champ result vaut "success"
    seuil_echecs: int = SEUIL_ECHECS    # seuils réellement appliqués
    seuil_comptes: int = SEUIL_COMPTES
    nb_echecs_sans_ip: int = 0   # 4625 sans IP source, non attribuables


_RESEAUX = [ipaddress.ip_network(r) for r in RESEAUX_INTERNES]


def _pl(n: int, singulier: str, pluriel: str) -> str:
    """'1 compte' / '2 comptes' : accorde le mot avec le nombre."""
    return f"{n} {singulier if n <= 1 else pluriel}"


def est_interne(ip: str) -> bool:
    """Vrai si l'IP appartient à RESEAUX_INTERNES ; une IP invalide n'est pas interne."""
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(adresse in reseau for reseau in _RESEAUX
               if adresse.version == reseau.version)


def _classer(ip, nb_echecs, nb_comptes, seuil_echecs, seuil_comptes):
    """Renvoie (catégorie, motif) pour une IP selon les seuils.

    L'ordre des tests compte : spraying d'abord (quelle que soit l'origine),
    puis force brute (IP externe), puis faux positif (interne, un seul compte) ;
    une IP interne à plusieurs comptes sous le seuil de comptes tombe dans le
    4e cas, sinon l'IP est simplement sous le seuil d'échecs.
    """
    interne = est_interne(ip)
    if nb_echecs >= seuil_echecs and nb_comptes >= seuil_comptes:
        return "spraying", (f"{nb_echecs} échecs sur {nb_comptes} comptes différents : "
                            "une même source essaie de nombreux comptes (password spraying)")
    if nb_echecs >= seuil_echecs and not interne:
        return "force_brute", (f"{nb_echecs} échecs sur {_pl(nb_comptes, 'compte', 'comptes')} depuis une "
                               "IP externe : acharnement sur peu de comptes (force brute)")
    if nb_echecs >= seuil_echecs and nb_comptes == 1:
        return "faux_positif_probable", (
            f"{nb_echecs} échecs sur un seul compte depuis le réseau interne : "
            "probablement un compte de service dont le mot de passe a expiré")
    if interne and nb_echecs >= seuil_echecs:
        return "sous_seuil", (f"IP interne avec {nb_comptes} comptes différents, "
                              f"sous le seuil de {seuil_comptes} comptes")
    return "sous_seuil", f"{nb_echecs} échecs, sous le seuil de {seuil_echecs}"


def etape1_detection(evts: list[Evenement], seuil_echecs: int = SEUIL_ECHECS,
                     seuil_comptes: int = SEUIL_COMPTES) -> ResultatDetection:
    """Repère les IP à rafales d'échecs (4625) et les classe."""
    par_ip = defaultdict(list)
    incoherences = 0
    total = 0
    sans_ip = 0
    for e in evts:
        if e.event_id != EVT_ECHEC:
            continue
        if not e.src_ip:
            sans_ip += 1
            continue
        total += 1
        par_ip[e.src_ip].append(e)
        if e.result == "success":
            incoherences += 1

    suspectes, ecartees = [], []
    for ip, liste in par_ip.items():
        comptes = _premieres_graphies(e.account for e in liste)
        categorie, motif = _classer(ip, len(liste), len(comptes),
                                    seuil_echecs, seuil_comptes)
        profil = ProfilIP(
            ip=ip, nb_echecs=len(liste), comptes=comptes,
            hosts=_premieres_graphies(e.host for e in liste),
            debut=min(e.timestamp for e in liste),
            fin=max(e.timestamp for e in liste),
            categorie=categorie, motif=motif)
        if categorie in ("spraying", "force_brute"):
            suspectes.append(profil)
        elif profil.nb_echecs >= seuil_echecs:
            ecartees.append(profil)
    suspectes.sort(key=lambda p: p.debut)
    ecartees.sort(key=lambda p: p.debut)
    return ResultatDetection(suspectes, ecartees, total, len(par_ip), incoherences,
                             seuil_echecs, seuil_comptes, sans_ip)


def formater_heure(dt: datetime, multi_jours: bool) -> str:
    """HH:MM, ou JJ/MM HH:MM si les données couvrent plusieurs jours."""
    return dt.strftime("%d/%m %H:%M" if multi_jours else "%H:%M")


_PROFILS = {"spraying": "password spraying", "force_brute": "force brute"}


def expliquer_etape1(det: ResultatDetection, multi_jours: bool) -> str:
    """Explication en français, destinée à un lecteur non technique."""
    lignes = ["=== ÉTAPE 1 : DÉTECTION DES ATTAQUES PAR MOTS DE PASSE ==="]
    lignes.append(
        f"Recherche : les échecs de connexion (événement 4625), regroupés par adresse IP "
        f"source. Une IP est signalée à partir de {det.seuil_echecs} échecs ; au moins "
        f"{det.seuil_comptes} comptes visés indiquent un password spraying (un mot de passe "
        f"courant testé sur beaucoup de comptes), moins indiquent une force brute.")
    lignes.append(
        f"Résultat : {_pl(det.nb_echecs_total, 'échec de connexion analysé', 'échecs de connexion analysés')}, "
        f"venant de {_pl(det.nb_ip_analysees, 'adresse IP', 'adresses IP')} ; "
        f"{_pl(len(det.suspectes), 'suspecte', 'suspectes')}"
        + (f" ; {_pl(det.nb_echecs_sans_ip, 'échec', 'échecs')} sans IP source, "
           f"non attribuable{'' if det.nb_echecs_sans_ip == 1 else 's'}"
           if det.nb_echecs_sans_ip else "") + ".")
    for p in det.suspectes:
        lignes.append(
            f"  - {p.ip} : {p.nb_echecs} échecs, {_pl(len(p.comptes), 'compte', 'comptes')}, "
            f"{'machine visée' if len(p.hosts) == 1 else 'machines visées'} : "
            f"{', '.join(p.hosts)}, de "
            f"{formater_heure(p.debut, multi_jours)} à {formater_heure(p.fin, multi_jours)}"
            f" -> profil {_PROFILS[p.categorie]}.")
    for p in det.ecartees:
        lignes.append(
            f"  - Écartée : {p.ip} ({p.nb_echecs} échecs, "
            f"{'compte' if len(p.comptes) == 1 else 'comptes'} : {', '.join(p.comptes)}) -> {p.motif}.")
    if det.nb_incoherences_result:
        lignes.append(
            f"Note : {det.nb_incoherences_result} de ces échecs portent pourtant "
            f"result = \"success\" dans le journal ; cette incohérence est ignorée, "
            f"l'identifiant d'événement 4625 fait foi.")
    if det.suspectes:
        lignes.append(
            f"-> {_pl(len(det.suspectes), 'IP suspecte', 'IP suspectes')} à examiner : "
            f"l'étape 2 cherche si l'une d'elles a fini par se connecter avec succès.")
    else:
        lignes.append(
            "-> Aucune IP ne dépasse les seuils : les étapes suivantes n'ont rien sur "
            "quoi s'appuyer.")
    return "\n".join(lignes)


# --- Étape 2 : pivot --------------------------------------------------------
@dataclass
class Compromission:
    """Première connexion réussie d'une IP suspecte sur un couple compte/machine."""
    ip: str
    compte: str
    host: str
    t0: datetime
    logon_type: int | None
    profil: ProfilIP


@dataclass
class ResultatPivot:
    compromissions: list[Compromission]   # triées par t0
    non_abouties: list[ProfilIP]          # IP suspectes sans connexion réussie


def etape2_pivot(evts: list[Evenement], det: ResultatDetection) -> ResultatPivot:
    """Cherche les connexions réussies (4624) depuis les IP suspectes.

    Seules comptent les connexions à partir du premier échec de l'IP : une
    connexion antérieure est celle d'un utilisateur légitime. Une compromission
    par couple (compte, machine), à la date de sa première connexion.
    """
    compromissions, non_abouties = [], []
    for profil in det.suspectes:
        couples = {}
        for e in evts:  # evts est trié : la première occurrence est la plus ancienne
            if (e.event_id == EVT_SUCCES and e.src_ip == profil.ip
                    and e.timestamp >= profil.debut):
                couples.setdefault((_cle(e.account), _cle(e.host)), e)
        if not couples:
            non_abouties.append(profil)
        for e in couples.values():
            compromissions.append(Compromission(
                profil.ip, e.account, e.host, e.timestamp, e.logon_type, profil))
    compromissions.sort(key=lambda c: c.t0)
    return ResultatPivot(compromissions, non_abouties)


_TYPES_CONNEXION = {3: "par accès réseau", 2: "par ouverture de session interactive",
                    10: "par bureau à distance (RDP)"}


def expliquer_etape2(piv: ResultatPivot, multi_jours: bool) -> str:
    """Explication en français, destinée à un lecteur non technique."""
    lignes = ["=== ÉTAPE 2 : L'ATTAQUE A-T-ELLE ABOUTI ? ==="]
    if not piv.compromissions and not piv.non_abouties:
        lignes.append(
            "Recherche : les connexions réussies (événement 4624) depuis les IP suspectes.")
        lignes.append("Résultat : aucune IP suspecte à l'étape 1, donc rien à pivoter.")
        lignes.append("-> Pas de compromission à reconstituer.")
        return "\n".join(lignes)

    lignes.append(
        "Recherche : pour chaque IP suspecte, les connexions réussies (événement 4624) "
        "survenues après son premier échec : l'attaquant dispose alors d'un mot de passe valide.")
    lignes.append(
        f"Résultat : {_pl(len(piv.compromissions), 'compromission', 'compromissions')} "
        f"; {_pl(len(piv.non_abouties), 'IP suspecte', 'IP suspectes')} sans connexion réussie.")
    for c in piv.compromissions:
        mode = _TYPES_CONNEXION.get(c.logon_type, "de type inconnu")
        origine = ("mot de passe probablement deviné par l'attaquant"
                   if _dans(c.compte, c.profil.comptes) else
                   "compte qui ne figurait pas parmi les comptes visés par les échecs")
        lignes.append(
            f"  - L'attaque depuis {c.ip} a abouti : le compte {c.compte} s'est connecté à "
            f"{c.host} à {formater_heure(c.t0, multi_jours)}, {mode} ; {origine}.")
    for p in piv.non_abouties:
        lignes.append(
            f"  - L'attaque depuis {p.ip} n'a pas abouti : aucune connexion réussie "
            f"depuis cette IP.")
    if piv.compromissions:
        cibles = ", ".join(
            f"{c.host} après {formater_heure(c.t0, multi_jours)}"
            for c in piv.compromissions)
        lignes.append(
            f"-> L'étape 3 reconstitue l'activité sur {'la machine' if len(piv.compromissions) == 1 else 'les machines'} "
            f"touchée{'' if len(piv.compromissions) == 1 else 's'} : {cibles}.")
    else:
        lignes.append(
            "-> Aucune connexion réussie : il n'y a pas d'activité à reconstituer ; "
            "ces tentatives sont à bloquer et surveiller.")
    return "\n".join(lignes)


# --- Étape 3 : chronologie --------------------------------------------------
@dataclass
class EvenementQualifie:
    """Un événement du périmètre compromis, qualifié et décrit en français."""
    evt: Evenement
    nature: str  # connexion_initiale | connexion | mouvement_lateral | connexion_a_verifier |
    #              processus_suspect | processus_benin | tache_planifiee | creation_compte |
    #              ajout_groupe | ajout_groupe_privilegie | effacement_journal | autre
    description: str
    suspect: bool
    commande_decodee: str | None = None
    sans_marqueur: bool = False   # commande d'un compte suivi, sans marqueur connu


@dataclass
class Chronologie:
    """Activité post-compromission pour une compromission."""
    compromission: Compromission
    evenements: list[EvenementQualifie]
    comptes_suivis: list[str]   # compte compromis, puis comptes créés par l'attaquant


def _option(jeton: str) -> str:
    """Option en minuscules, « /x » ramené à « -x » (PowerShell accepte les deux)."""
    jeton = jeton.lower()
    return "-" + jeton[1:] if jeton.startswith("/") else jeton


def _est_option_encodee(jeton: str) -> bool:
    """-ec, ou tout préfixe d'au moins 2 caractères de -EncodedCommand (-e, -enc...)."""
    t = _option(jeton)
    return t == "-ec" or (len(t) >= 2 and OPTION_ENCODEE.startswith(t))


def _est_option_sans_profil(jeton: str) -> bool:
    """Préfixe d'au moins 4 caractères de -NoProfile (-nop, -nopr...)."""
    t = _option(jeton)
    return len(t) >= 4 and OPTION_SANS_PROFIL.startswith(t)


def _contexte_powershell(ligne: str, processus: str = "") -> bool:
    """Vrai si le processus ou un mot de la ligne est PowerShell.

    Les options abrégées (-e, /e...) ne sont lues qu'en contexte PowerShell :
    ailleurs, « xcopy /e » ou « findstr -e » sont des usages courants.
    """
    if _nom_processus(processus) in EXECUTABLES_POWERSHELL:
        return True
    return any(_nom_processus(m.strip('"')) in EXECUTABLES_POWERSHELL
               for m in (ligne or "").split())


def decoder_commande(ligne: str, processus: str = "") -> str | None:
    """Décode l'argument de -EncodedCommand (ou d'une abréviation : -e, -ec, -enc, /enc...).

    None s'il n'y a pas de paramètre encodé ou hors contexte PowerShell ;
    "non décodable" si le décodage base64 puis UTF-16LE échoue ou si l'argument manque.
    """
    if not _contexte_powershell(ligne, processus):
        return None
    mots = (ligne or "").split()
    for i, mot in enumerate(mots):
        if _est_option_encodee(mot):
            if i + 1 >= len(mots):
                return "non décodable"
            try:
                texte = base64.b64decode(mots[i + 1], validate=True).decode("utf-16-le")
            except (binascii.Error, ValueError):  # UnicodeDecodeError est un ValueError
                return "non décodable"
            return texte.rstrip("\x00")
    return None


def _nom_processus(chemin) -> str:
    """Nom de fichier en minuscules, quel que soit le style de chemin."""
    return ntpath.basename(str(chemin or "").replace("/", "\\")).lower()


_SEPARATEURS = re.compile(r"[\s(),;'\"{}|=.]+")
_EXTENSIONS_EXE = (".exe", ".com", ".bat", ".cmd")


def _marqueurs_presents(ligne: str, processus: str = "") -> bool:
    """Vrai si un marqueur suspect figure comme mot entier parmi les arguments.

    L'exécutable (premier mot) est ignoré : iexplore.exe ou un chemin contenant
    « hidden » ne comptent pas, pas plus que -nopause pour -nop. Les options
    PowerShell abrégées (-ec, -enc, /e, -nop...) ne comptent qu'en contexte PowerShell.
    """
    powershell = _contexte_powershell(ligne, processus)
    mots = ligne.split(None, 1)
    if mots and mots[0].lower().strip('"').endswith(_EXTENSIONS_EXE):
        ligne = mots[1] if len(mots) > 1 else ""
    jetons = {j for j in _SEPARATEURS.split(ligne.lower()) if j}
    if any(m in jetons for m in MARQUEURS_CMD_SUSPECTS):
        return True
    return powershell and any(_est_option_encodee(j) or _est_option_sans_profil(j)
                              for j in jetons)


def _compte_suivi(compte: str, c: Compromission) -> str:
    """« le compte compromis X » ou « le compte créé par l'attaquant X »."""
    if _cle(compte) == _cle(c.compte):
        return f"le compte compromis {compte}"
    return f"le compte créé par l'attaquant {compte}"


def qualifier_evenement(e: Evenement, c: Compromission,
                        suivis: list[str] | None = None) -> EvenementQualifie:
    """Qualifie un événement du périmètre de la compromission c.

    suivis : comptes suivis à ce stade (par défaut, le seul compte compromis).
    """
    suivis = [c.compte] if suivis is None else suivis
    d = e.details
    if e.event_id == EVT_SUCCES:
        if (e.timestamp == c.t0 and _cle(e.host) == _cle(c.host)
                and _cle(e.account) == _cle(c.compte)):
            return EvenementQualifie(
                e, "connexion_initiale",
                f"connexion de {e.account} depuis {e.src_ip or 'IP inconnue'} "
                f"(début de la compromission)", True)
        if _cle(e.host) != _cle(c.host):
            if e.logon_type in TYPES_CONNEXION_LOCALE:
                compte = _compte_suivi(e.account, c).replace("le compte", "du compte", 1)
                return EvenementQualifie(
                    e, "connexion_a_verifier",
                    f"connexion interactive {compte} sur {e.host} : à vérifier "
                    f"(poste habituel de l'utilisateur ?)", True)
            return EvenementQualifie(
                e, "mouvement_lateral",
                f"connexion de {e.account} sur {e.host} depuis "
                f"{e.src_ip or 'IP inconnue'} (mouvement latéral)", True)
        if e.src_ip and e.src_ip == c.ip:
            return EvenementQualifie(
                e, "connexion",
                f"nouvelle connexion de {e.account} depuis l'IP d'attaque {e.src_ip}", True)
        return EvenementQualifie(
            e, "connexion",
            f"connexion de {e.account} depuis {e.src_ip or 'IP inconnue'}", False)
    if e.event_id == EVT_PROCESSUS:
        processus = _nom_processus(d.get("process"))
        parent = _nom_processus(d.get("parent_process"))
        ligne = str(d.get("command_line") or "")
        office = parent in PARENTS_BUREAUTIQUES and processus in INTERPRETEURS
        marqueur = _marqueurs_presents(ligne, processus)
        if office or marqueur:
            decodee = decoder_commande(ligne, processus)
            motif = (f"lancé par {parent}" if office else "avec des options suspectes")
            desc = f"{processus or 'processus inconnu'} {motif} (exécution suspecte) : {ligne}"
            if decodee is not None:
                desc += f" ; commande décodée : {decodee} (commande encodée, contenu masqué)"
            if re.search(r"https?://", ligne, re.IGNORECASE):
                desc += " (téléchargement d'un fichier depuis Internet)"
            return EvenementQualifie(e, "processus_suspect", desc, True, decodee)
        if e.account and _dans(e.account, suivis):
            return EvenementQualifie(
                e, "processus_suspect",
                f"{processus or 'processus inconnu'} : commande exécutée par "
                f"{_compte_suivi(e.account, c)} (aucun marqueur connu) : {ligne or 'ligne inconnue'}",
                True, sans_marqueur=True)
        return EvenementQualifie(
            e, "processus_benin",
            f"processus {processus or 'inconnu'} lancé par {parent or 'inconnu'} "
            f"(aucun marqueur suspect)", False)
    if e.event_id == EVT_TACHE:
        return EvenementQualifie(
            e, "tache_planifiee",
            f"tâche planifiée créée : {d.get('task_name') or 'nom inconnu'}", True)
    if e.event_id == EVT_CREATION_COMPTE:
        return EvenementQualifie(
            e, "creation_compte",
            f"compte local créé : {d.get('new_account') or 'nom inconnu'}", True)
    if e.event_id == EVT_AJOUT_GROUPE:
        groupe = str(d.get("group") or "groupe inconnu")
        membre = d.get("member") or "membre inconnu"
        if groupe.lower() in GROUPES_PRIVILEGIES:
            return EvenementQualifie(
                e, "ajout_groupe_privilegie",
                f"{membre} ajouté au groupe {groupe} (groupe à privilèges)", True)
        return EvenementQualifie(
            e, "ajout_groupe", f"{membre} ajouté au groupe {groupe}", False)
    if e.event_id == EVT_EFFACEMENT:
        return EvenementQualifie(
            e, "effacement_journal", "journal de sécurité effacé", True)
    return EvenementQualifie(e, "autre", f"événement {e.event_id}", False)


def etape3_chronologie(evts: list[Evenement], piv: ResultatPivot) -> list[Chronologie]:
    """Reconstitue l'activité après chaque compromission.

    Périmètre : événements (hors 4625) à partir de t0 sur la machine compromise,
    ou faits par un compte suivi, ou ajoutant un compte suivi à un groupe. Un
    compte créé (4720) dans le périmètre est suivi à son tour. Comptes et
    machines sont comparés sans tenir compte de la casse, comme sous Windows.
    """
    chronos = []
    for c in piv.compromissions:
        suivis = [c.compte]
        retenus = []
        for e in evts:  # trié chronologiquement
            if e.timestamp < c.t0 or e.event_id == EVT_ECHEC:
                continue
            membre = e.details.get("member") if e.event_id == EVT_AJOUT_GROUPE else None
            if (_cle(e.host) == _cle(c.host) or _dans(e.account, suivis)
                    or (membre and _dans(membre, suivis))):
                retenus.append(qualifier_evenement(e, c, suivis))
                if e.event_id == EVT_CREATION_COMPTE:
                    nouveau = e.details.get("new_account")
                    if nouveau and not _dans(nouveau, suivis):
                        suivis.append(nouveau)
        chronos.append(Chronologie(c, retenus, suivis))
    return chronos


def expliquer_etape3(chronos: list[Chronologie], multi_jours: bool) -> str:
    """Explication en français, destinée à un lecteur non technique."""
    lignes = ["=== ÉTAPE 3 : QUE FAIT L'ATTAQUANT APRÈS L'INTRUSION ? ==="]
    if not chronos:
        lignes.append(
            "Recherche : l'activité des comptes compromis après leur première connexion.")
        lignes.append("Résultat : aucune compromission à l'étape 2, donc aucune chronologie.")
        lignes.append("-> Pas d'action de remédiation à planifier pour cette étape.")
        return "\n".join(lignes)

    for ch in chronos:
        c = ch.compromission
        crees = ch.comptes_suivis[1:]
        comptes = ", ".join(ch.comptes_suivis)
        lignes.append(
            f"Recherche : sur {c.host}, tout ce qui s'est passé à partir de "
            f"{formater_heure(c.t0, multi_jours)} (connexion de {c.compte}), "
            f"{_pl(len(ch.comptes_suivis), 'compte suivi', 'comptes suivis')} : {comptes}.")
        if crees:
            lignes.append(
                f"  Le périmètre a été étendu {'au compte créé' if len(crees) == 1 else 'aux comptes créés'} "
                f"par l'attaquant : {', '.join(crees)} (ses actions sur d'autres machines "
                f"sont aussi suivies).")
        nb_susp = sum(1 for q in ch.evenements if q.suspect)
        lignes.append(
            f"Résultat : {_pl(len(ch.evenements), 'événement', 'événements')} dont "
            f"{_pl(nb_susp, 'suspect', 'suspects')} (marqués [!]).")
        for q in ch.evenements:
            marque = "[!] " if q.suspect else "    "
            lignes.append(
                f"  {marque}{formater_heure(q.evt.timestamp, multi_jours)}  "
                f"{q.evt.host}  {q.description}")
    lignes.append(
        "-> L'étape 4 transforme ces constats en plan d'action : isoler les machines, "
        "désactiver les comptes, supprimer les tâches et retirer les droits obtenus.")
    return "\n".join(lignes)


# --- Étape 4 : plan d'action et gravité -------------------------------------
PRIORITES = ("IMMÉDIAT", "COURT TERME", "SUIVI")


@dataclass(frozen=True)
class Action:
    """Une action de remédiation, toujours rattachée à un fait observé."""
    priorite: str
    fait: str
    action: str


def etape4_plan(det: ResultatDetection, piv: ResultatPivot,
                chronos: list[Chronologie], multi_jours: bool = False) -> list[Action]:
    """Plan d'action : chaque action découle d'un fait observé aux étapes 1 à 3.

    Dédoublonné (une action identique n'apparaît qu'une fois, avec le premier
    fait qui l'a motivée), trié par priorité puis par ordre d'apparition.
    """
    def h(dt):
        return formater_heure(dt, multi_jours)

    actions = []

    def ajouter(priorite, fait, action):
        actions.append(Action(priorite, fait, action))

    for p in det.suspectes:
        ajouter("IMMÉDIAT",
                f"{p.ip} a échoué {p.nb_echecs} fois à se connecter entre {h(p.debut)} et {h(p.fin)}",
                f"Bloquer l'IP {p.ip} au pare-feu et au proxy")
    for ch in chronos:
        c = ch.compromission
        fait_c = (f"Connexion de l'attaquant confirmée sur {c.host} à {h(c.t0)} "
                  f"avec {c.compte}")
        ajouter("IMMÉDIAT", fait_c, f"Isoler {c.host} du réseau")
        ajouter("IMMÉDIAT", fait_c,
                f"Réinitialiser le mot de passe de {c.compte} et révoquer ses sessions "
                f"(le déconnecter partout)")
        for q in ch.evenements:
            e, d, quand = q.evt, q.evt.details, h(q.evt.timestamp)
            if q.nature == "creation_compte":
                nouveau = d.get("new_account") or "nom inconnu"
                ajouter("IMMÉDIAT",
                        f"Compte {nouveau} créé sur {e.host} à {quand} par {e.account}",
                        f"Désactiver le compte {nouveau}")
            elif q.nature in ("ajout_groupe", "ajout_groupe_privilegie"):
                membre = d.get("member") or "membre inconnu"
                groupe = d.get("group") or "groupe inconnu"
                prive = q.nature == "ajout_groupe_privilegie"
                ajouter("IMMÉDIAT" if prive else "COURT TERME",
                        f"{membre} ajouté au groupe {'à privilèges ' if prive else ''}"
                        f"{groupe} sur {e.host} à {quand}",
                        f"Retirer {membre} du groupe {groupe}")
            elif q.nature == "tache_planifiee":
                nom = d.get("task_name") or "nom inconnu"
                ajouter("COURT TERME",
                        f"Tâche planifiée {nom} créée sur {e.host} à {quand}",
                        f"Supprimer la tâche planifiée {nom} sur {e.host}")
            elif q.nature == "processus_suspect" and q.sans_marqueur:
                ajouter("COURT TERME",
                        f"Commandes exécutées sur {e.host} par {e.account} après l'intrusion "
                        f"(première à {quand})",
                        f"Collecter les preuves sur {e.host} (mémoire, disque) et analyser "
                        f"les commandes exécutées par {e.account}")
            elif q.nature == "processus_suspect":
                cmd = q.commande_decodee
                if not cmd or cmd == "non décodable":
                    cmd = str(d.get("command_line") or "commande inconnue")
                ajouter("COURT TERME",
                        f"Commande suspecte exécutée sur {e.host} à {quand} par {e.account}",
                        f"Collecter les preuves sur {e.host} (mémoire, disque) "
                        f"et analyser la commande : {cmd}")
            elif q.nature == "effacement_journal":
                ajouter("COURT TERME",
                        f"Journal de sécurité effacé sur {e.host} à {quand} par {e.account}",
                        f"Traçabilité locale perdue sur {e.host} : "
                        f"s'appuyer sur le SIEM (outil central de collecte des journaux) "
                        f"et les sauvegardes")
            elif q.nature == "mouvement_lateral":
                ajouter("IMMÉDIAT",
                        f"Connexion de {e.account} sur {e.host} à {quand}, "
                        f"après l'intrusion sur {c.host} (rebond)",
                        f"Isoler {e.host} du réseau et étendre l'investigation")
            elif q.nature == "connexion_a_verifier":
                ajouter("COURT TERME",
                        f"Connexion interactive de {e.account} sur {e.host} à {quand}, "
                        f"après l'intrusion sur {c.host}",
                        f"Vérifier auprès de l'utilisateur la connexion sur {e.host} à {quand}")
    for p in piv.non_abouties:
        ajouter("SUIVI",
                f"{p.ip} a visé {_pl(len(p.comptes), 'compte', 'comptes')} sans jamais se connecter",
                f"Surveiller les comptes visés par {p.ip} ({len(p.comptes)}) et imposer le MFA "
                f"(double authentification)")
    for p in det.ecartees:
        if p.categorie == "faux_positif_probable" and p.comptes:
            ajouter("SUIVI",
                    f"{p.nb_echecs} échecs de {p.comptes[0]} depuis {p.ip} (réseau interne) "
                    f"sur {', '.join(p.hosts)}",
                    f"Vérifier le mot de passe du compte de service {p.comptes[0]} "
                    f"sur {', '.join(p.hosts)}")
    for p in det.suspectes:
        if p.categorie == "spraying":
            ajouter("SUIVI",
                    f"{p.ip} a testé {_pl(len(p.comptes), 'compte', 'comptes')} (password spraying)",
                    f"Revoir la robustesse des mots de passe des {len(p.comptes)} comptes visés par {p.ip}")

    # une action identique (casse des noms Windows ignorée) n'apparaît qu'une
    # fois, avec sa priorité la plus haute
    retenues = {}
    for a in actions:
        cle = _cle(a.action)
        if cle not in retenues or (PRIORITES.index(a.priorite)
                                   < PRIORITES.index(retenues[cle].priorite)):
            retenues[cle] = a
    uniques = list(retenues.values())
    return sorted(uniques, key=lambda a: PRIORITES.index(a.priorite))


def evaluer_gravite(piv: ResultatPivot, chronos: list[Chronologie]) -> str:
    """CRITIQUE, ÉLEVÉE, MODÉRÉE ou FAIBLE selon les constats des étapes 2 et 3."""
    graves = {"ajout_groupe_privilegie", "effacement_journal", "mouvement_lateral"}
    if any(q.nature in graves for ch in chronos for q in ch.evenements):
        return "CRITIQUE"
    if piv.compromissions:
        return "ÉLEVÉE"
    if piv.non_abouties:
        return "MODÉRÉE"
    return "FAIBLE"


def _justifier_gravite(gravite: str, piv: ResultatPivot,
                       chronos: list[Chronologie]) -> str:
    """Justification de la gravité, limitée à ce qui a été observé."""
    constats = []
    for ch in chronos:
        for q in ch.evenements:
            if q.nature == "ajout_groupe_privilegie":
                constats.append(f"ajout de {q.evt.details.get('member') or 'un compte'} au groupe "
                                f"{q.evt.details.get('group') or 'à privilèges'}")
            elif q.nature == "mouvement_lateral":
                constats.append(f"rebond vers {q.evt.host}")
            elif q.nature == "effacement_journal":
                constats.append(f"effacement du journal de sécurité de {q.evt.host}")
    if gravite == "CRITIQUE":
        return ("l'attaquant a étendu son emprise (" + ", ".join(constats) + ")"
                if constats else "l'attaquant a étendu son emprise")
    if gravite == "ÉLEVÉE" and piv.compromissions:
        return ("l'attaquant s'est connecté avec succès à "
                + ", ".join(_premieres_graphies(c.host for c in piv.compromissions))
                + ", sans extension d'emprise constatée")
    if gravite == "MODÉRÉE":
        return "des attaques ont été détectées mais aucune connexion réussie"
    return "aucune attaque significative détectée"


def expliquer_etape4(actions: list[Action], gravite: str, piv: ResultatPivot | None = None,
                     chronos: list[Chronologie] | None = None,
                     nb_ip_suspectes: int = 0) -> str:
    """Explication en français, destinée à un lecteur non technique."""
    lignes = ["=== ÉTAPE 4 : PLAN D'ACTION ET GRAVITÉ ==="]
    piv = piv or ResultatPivot([], [])
    chronos = chronos or []
    nb_evts = sum(len(ch.evenements) for ch in chronos)
    lignes.append(
        f"Recherche : à partir de {_pl(nb_ip_suspectes, 'IP suspecte', 'IP suspectes')}, "
        f"{_pl(len(piv.compromissions), 'compromission', 'compromissions')} et "
        f"{_pl(nb_evts, 'événement post-intrusion', 'événements post-intrusion')}, "
        f"les mesures à prendre ; chaque action est rattachée au fait observé qui la justifie.")
    lignes.append(
        f"Résultat : gravité {gravite} : {_justifier_gravite(gravite, piv, chronos)} ; "
        f"{_pl(len(actions), 'action', 'actions')} proposée"
        f"{'' if len(actions) <= 1 else 's'}.")
    for prio in PRIORITES:
        groupe = [a for a in actions if a.priorite == prio]
        if not groupe:
            continue
        lignes.append(f"  {prio} :")
        for a in groupe:
            lignes.append(f"    - {a.fait} -> {a.action}")
    lignes.append(
        "-> L'étape 5 extrait les indicateurs de compromission (IP, comptes, tâches, "
        "commandes, empreintes) pour les partager et les enrichir.")
    return "\n".join(lignes)


# --- Étape 5 : IOC et enrichissement ----------------------------------------
_LIBELLES_IOC = {
    "ip-src": "IP d'attaque", "ip-dst": "IP de destination", "domain": "domaine",
    "url": "adresse web", "md5": "empreinte de fichier", "sha1": "empreinte de fichier",
    "sha256": "empreinte de fichier", "text": "compte créé, tâche ou commande",
    "target-user": "compte compromis", "target-machine": "machine touchée",
}
_LIBELLES_STATUT = {
    "ok": "verdict obtenu", "inconnu": "inconnu de VirusTotal",
    "non_soumis": "non soumis", "non_applicable": "non applicable",
    "cle_absente": "clé absente", "cle_invalide": "clé refusée",
    "indisponible": "source indisponible",
}
# Compteurs de last_analysis_stats additionnés pour le nombre de moteurs
_STATS_VT = ("malicious", "suspicious", "harmless", "undetected", "timeout",
             "type-unsupported", "failure", "confirmed-timeout")


def _verdict_vt(ioc) -> str:
    """Résumé lisible du résultat VirusTotal d'un IOC enrichi."""
    donnees = ioc.enrichissement or {}
    if ioc.statut_enrichissement == "ok":
        total = sum(v for k, v in donnees.items()
                    if k in _STATS_VT and isinstance(v, int))
        malveillant = donnees.get("malicious") or 0
        return (f"{malveillant} {'moteur' if malveillant <= 1 else 'moteurs'} sur {total} "
                f"le {'juge' if malveillant <= 1 else 'jugent'} malveillant")
    return donnees.get("message") or _LIBELLES_STATUT.get(
        ioc.statut_enrichissement, str(ioc.statut_enrichissement))


# Pays courants : code ISO 3166 alpha-2 → nom français (repli : le code seul)
_PAYS = {
    "US": "États-Unis", "FR": "France", "DE": "Allemagne", "NL": "Pays-Bas",
    "GB": "Royaume-Uni", "RU": "Russie", "CN": "Chine", "UA": "Ukraine", "BR": "Brésil",
    "IN": "Inde", "JP": "Japon", "KR": "Corée du Sud", "KP": "Corée du Nord",
    "IR": "Iran", "CA": "Canada", "IT": "Italie", "ES": "Espagne", "PL": "Pologne",
    "RO": "Roumanie", "BG": "Bulgarie", "SE": "Suède", "CH": "Suisse", "BE": "Belgique",
    "SG": "Singapour", "HK": "Hong Kong", "TW": "Taïwan", "VN": "Viêt Nam",
    "TR": "Turquie", "IL": "Israël", "ZA": "Afrique du Sud", "AU": "Australie",
    "MX": "Mexique", "AR": "Argentine", "ID": "Indonésie", "TH": "Thaïlande",
    "MY": "Malaisie", "SC": "Seychelles", "PA": "Panama", "LT": "Lituanie",
    "LV": "Lettonie", "MD": "Moldavie", "KZ": "Kazakhstan", "BY": "Biélorussie",
}
_CATEGORIES_VT = {"malicious": "malveillant", "suspicious": "suspect",
                  "harmless": "sans danger", "undetected": "non détecté"}
EXPLICATION_REPUTATION = (
    "  Note : la réputation est le score attribué par la communauté VirusTotal ; "
    "un score négatif signifie que l'élément est jugé malveillant.")


def _pays(code) -> str:
    code = str(code).upper()
    return f"{_PAYS[code]} ({code})" if code in _PAYS else code


def _date_vt(epoch) -> str:
    return f"{datetime.fromtimestamp(epoch, timezone.utc):%d/%m/%Y %H:%M} UTC"


def _lignes_detail_vt(ioc) -> list:
    """Lignes de détail VirusTotal (français clair) d'un IOC enrichi ; vides si absentes."""
    d = ioc.enrichissement or {}
    if ioc.statut_enrichissement != "ok" or not isinstance(d, dict):
        return []
    lignes = []
    reseau = []
    if d.get("as_owner"):
        reseau.append(f"opérateur réseau : {d['as_owner']}")
    asn = []
    if d.get("asn"):
        asn.append(f"AS{d['asn']}")
    if d.get("network"):
        asn.append(f"réseau {d['network']}")
    if d.get("country") or reseau or asn:
        txt = f"Pays : {_pays(d['country'])}" if d.get("country") else ""
        if reseau or asn:
            op = reseau[0] if reseau else "réseau"
            if reseau:
                txt += (" — " if txt else "") + op
                if asn:
                    txt += f" ({', '.join(asn)})"
            else:
                txt += (" — " if txt else "") + ", ".join(asn)
        lignes.append(txt)
    if d.get("type_description") or d.get("meaningful_name"):
        lignes.append("Fichier : " + " — ".join(
            str(d[c]) for c in ("meaningful_name", "type_description") if d.get(c)))
    if any(isinstance(d.get(k), int) for k in _STATS_VT):
        total = sum(v for k, v in d.items() if k in _STATS_VT and isinstance(v, int))
        nb = lambda k: d.get(k) or 0
        morceaux = [_pl(nb("malicious"), "malveillant", "malveillants"),
                    _pl(nb("suspicious"), "suspect", "suspects"),
                    f"{nb('harmless')} sans danger",
                    _pl(nb("undetected"), "non détecté", "non détectés")]
        txt = f"Analyses : {', '.join(morceaux)} ({total} moteurs)"
        if d.get("last_analysis_date"):
            txt += f" — dernière analyse le {_date_vt(d['last_analysis_date'])}"
        lignes.append(txt)
    if d.get("moteurs"):
        sig = []
        for m in d["moteurs"]:
            cat = _CATEGORIES_VT.get(m.get("categorie"), m.get("categorie") or "")
            sig.append(f"{m['moteur']} ({cat}{' : ' + m['resultat'] if m.get('resultat') else ''})")
        txt = "Moteurs qui la signalent : " + ", ".join(sig)
        reste = (d.get("nb_moteurs_signales") or 0) - len(d["moteurs"])
        if reste > 0:
            txt += f" et {reste} autre{'s' if reste > 1 else ''}"
        lignes.append(txt)
    comm = []
    if d.get("reputation") is not None:
        comm.append(f"Réputation communautaire : {d['reputation']}")
    votes = d.get("total_votes")
    if isinstance(votes, dict):
        v = (f"votes : {votes.get('malicious') or 0} malveillants, "
             f"{votes.get('harmless') or 0} sans danger")
        comm.append(f"({v})" if comm else f"Votes de la communauté : {v}")
    txt = " ".join(comm)
    if d.get("tags"):
        txt += (" — " if txt else "") + "étiquettes : " + ", ".join(map(str, d["tags"]))
    if txt:
        lignes.append(txt)
    if d.get("categories") and isinstance(d["categories"], dict):
        lignes.append("Catégories : " + ", ".join(
            sorted({str(c) for c in d["categories"].values()})))
    if d.get("lien"):
        lignes.append(f"Fiche VirusTotal : {d['lien']}")
    return lignes


def expliquer_etape5(iocs: list, comptage_vt: dict | None) -> str:
    """Explication en français, destinée à un lecteur non technique."""
    lignes = ["=== ÉTAPE 5 : IOC ET ENRICHISSEMENT ==="]
    lignes.append(
        "Recherche : les indicateurs de compromission (IOC), c'est-à-dire les traces "
        "réutilisables pour détecter l'attaquant ailleurs, tirés des étapes précédentes : "
        "IP d'attaque (étape 1), comptes et machines compromis (étape 2), comptes créés, "
        "tâches planifiées, commandes suspectes et les empreintes, adresses web, domaines "
        "et IP qu'elles contiennent (étape 3).")
    if not iocs:
        lignes.append("Résultat : aucun IOC extrait (aucune IP suspecte ni compromission).")
    else:
        par_libelle = {}
        for i in iocs:
            libelle = _libelle_ioc(i)
            par_libelle[libelle] = par_libelle.get(libelle, 0) + 1
        detail = ", ".join(f"{n} {_PLURIELS_LIBELLE.get(t, t) if n > 1 else t}"
                           for t, n in par_libelle.items())
        lignes.append(f"Résultat : {len(iocs)} IOC : {detail}.")
        for i in iocs:
            ligne = f"  - {i.valeur}  ({_libelle_ioc(i)})"
            if comptage_vt is not None and i.statut_enrichissement:
                ligne += f"  → {_verdict_vt(i)}"
            lignes.append(ligne)
            if comptage_vt is not None:
                lignes += [f"      {l}" for l in _lignes_detail_vt(i)]
        if comptage_vt is not None and any(
                (i.enrichissement or {}).get("reputation") is not None
                for i in iocs if i.statut_enrichissement == "ok"):
            lignes.append(EXPLICATION_REPUTATION)
    if comptage_vt is None:
        lignes.append("  Vérification VirusTotal : enrichissement non demandé (option --enrichir).")
    else:
        bilan = ", ".join(f"{n} {_LIBELLES_STATUT.get(s, s)}" for s, n in comptage_vt.items())
        lignes.append(f"  Vérification VirusTotal : {bilan or 'aucun IOC à vérifier'}.")
        if any("RFC 5737" in ((i.enrichissement or {}).get("message") or "") for i in iocs):
            lignes.append(
                "  Note : certaines IP appartiennent aux plages de documentation RFC 5737 "
                "(adresses réservées aux exemples, inexistantes sur Internet) ; elles ne "
                "sont pas soumises car VirusTotal ne peut rien en dire.")
        lignes.append(
            "  Aucun fichier ni échantillon n'a été envoyé : seules des valeurs "
            "(IP, domaines, URL, empreintes) sont consultées.")
    lignes.append(
        f"-> IOC exportés dans {SORTIE_MISP} (import MISP) et {SORTIE_STIX} "
        f"(STIX 2.1, pour une plateforme de renseignement sur la menace).")
    return "\n".join(lignes)


# --- Enchaînement, rapport et ligne de commande -----------------------------
@dataclass
class Investigation:
    """Résultats de bout en bout d'une investigation sur un fichier de logs."""
    chemin: str
    evts: list[Evenement]
    det: ResultatDetection
    piv: ResultatPivot
    chronos: list[Chronologie]
    actions: list[Action]
    gravite: str
    iocs: list
    comptage_vt: dict[str, int] | None
    multi_jours: bool


def investiguer(chemin: str, enrichir: bool = False, client_vt=None) -> Investigation:
    """Enchaîne les étapes 1 à 5 ; lève ErreurChargement si le fichier est inexploitable."""
    evts = charger_logs(chemin)
    multi_jours = len({e.timestamp.date() for e in evts}) > 1
    det = etape1_detection(evts)
    piv = etape2_pivot(evts, det)
    chronos = etape3_chronologie(evts, piv)
    actions = etape4_plan(det, piv, chronos, multi_jours)
    gravite = evaluer_gravite(piv, chronos)
    iocs = extraire_iocs(det, piv, chronos, est_interne=est_interne, multi_jours=multi_jours)
    comptage_vt = None
    if enrichir:
        if client_vt is None:
            client_vt = ClientVT(os.environ.get("VT_API_KEY"), VT_CACHE,
                                 ttl_heures=VT_TTL_HEURES, intervalle_s=VT_INTERVALLE_S,
                                 timeout_s=VT_TIMEOUT_S, max_essais=VT_MAX_ESSAIS)
        comptage_vt = enrichir_iocs(iocs, client_vt)
    return Investigation(chemin, evts, det, piv, chronos, actions, gravite, iocs,
                         comptage_vt, multi_jours)


def _periode(inv: Investigation, separateur: str = " → ") -> str:
    """Période couverte par les événements, en UTC, ou « aucune donnée »."""
    if not inv.evts:
        return "aucune donnée"
    return (f"{inv.evts[0].timestamp:%d/%m/%Y %H:%M}{separateur}"
            f"{inv.evts[-1].timestamp:%d/%m/%Y %H:%M} UTC")


def _explications(inv: Investigation) -> list[str]:
    """Textes des étapes 1 à 5, communs au rapport texte et au PDF."""
    return [
        expliquer_etape1(inv.det, inv.multi_jours),
        expliquer_etape2(inv.piv, inv.multi_jours),
        expliquer_etape3(inv.chronos, inv.multi_jours),
        expliquer_etape4(inv.actions, inv.gravite, inv.piv, inv.chronos,
                         nb_ip_suspectes=len(inv.det.suspectes)),
        expliquer_etape5(inv.iocs, inv.comptage_vt),
    ]


def rapport_texte(inv: Investigation) -> str:
    """Rapport complet : en-tête puis les explications des étapes 1 à 5."""
    periode = _periode(inv)
    en_tete = "\n".join([
        "RAPPORT D'INVESTIGATION AUTOMATISÉE",
        f"Fichier analysé : {inv.chemin}",
        f"Événements analysés : {_pl(len(inv.evts), 'événement', 'événements')}",
        f"Période couverte : {periode}",
        "Toutes les heures du rapport sont exprimées en UTC.",
        f"Gravité : {inv.gravite}",
    ])
    return "\n\n".join([en_tete, *_explications(inv)]) + "\n"


# --- Données du rapport PDF -------------------------------------------------
_LIBELLES_ROLE = {
    "ip_attaque": "IP d'attaque", "compte_compromis": "compte compromis",
    "machine": "machine touchée", "compte_cree": "compte créé",
    "tache": "tâche planifiée", "commande": "commande suspecte", "hash": "empreinte",
}
_LIBELLES_RESEAU = {"url": "URL", "domain": "domaine", "ip-dst": "IP contactée"}


_PLURIELS_LIBELLE = {
    "compte compromis": "comptes compromis", "machine touchée": "machines touchées",
    "compte créé": "comptes créés", "tâche planifiée": "tâches planifiées",
    "commande suspecte": "commandes suspectes", "empreinte": "empreintes",
    "domaine": "domaines", "IP contactée": "IP contactées",
    "empreinte de fichier": "empreintes de fichier", "adresse web": "adresses web",
    "IP de destination": "IP de destination",
}


def _libelle_ioc(ioc) -> str:
    """Libellé français du type d'un IOC, d'après son rôle puis son type MISP."""
    if ioc.role == "reseau":
        return _LIBELLES_RESEAU.get(ioc.type_misp, ioc.type_misp)
    return _LIBELLES_ROLE.get(ioc.role) or _LIBELLES_IOC.get(ioc.type_misp, ioc.type_misp)


def _enumerer(elements: list[str]) -> str:
    """'a', 'a et b', 'a, b et c'."""
    if len(elements) <= 1:
        return "".join(elements)
    return ", ".join(elements[:-1]) + " et " + elements[-1]


_GLOSES_PROFIL = {
    "spraying": "un même mot de passe essayé sur de nombreux comptes",
    "force_brute": "de nombreux mots de passe essayés sur un même compte",
}


def _synthese(inv: Investigation) -> list[str]:
    """Trois phrases non techniques : détection, intrusion, actions et gravité."""
    det, piv, h = inv.det, inv.piv, (lambda dt: formater_heure(dt, inv.multi_jours))
    nb_evts = _pl(len(inv.evts), "événement", "événements")

    if det.suspectes:
        glosees, morceaux = set(), []
        for p in det.suspectes:   # profil expliqué à sa première apparition seulement
            profil = _PROFILS[p.categorie]
            if p.categorie not in glosees:
                glosees.add(p.categorie)
                profil += f", c'est-à-dire {_GLOSES_PROFIL[p.categorie]} ;"
            else:
                profil += ","
            morceaux.append(f"{p.ip} ({profil} "
                            f"{_pl(len(p.comptes), 'compte visé', 'comptes visés')})")
        sources = _enumerer(morceaux)
        phrase1 = (f"L'analyse de {nb_evts} a mis en évidence "
                   f"{_pl(len(det.suspectes), 'source', 'sources')} qui "
                   f"{'a' if len(det.suspectes) == 1 else 'ont'} tenté de deviner des mots "
                   f"de passe : {sources}.")
    elif inv.evts:
        phrase1 = (f"L'analyse de {nb_evts} n'a révélé aucune tentative massive de "
                   f"deviner des mots de passe.")
    else:
        phrase1 = ("Le fichier analysé ne contient aucun événement exploitable : "
                   "aucune tentative d'attaque n'a pu y être recherchée.")

    if piv.compromissions:
        entrees = _enumerer([
            f"sur {c.host} avec le compte {c.compte} à {h(c.t0)} (depuis {c.ip})"
            for c in piv.compromissions])
        phrase2 = f"L'attaquant a réussi à entrer : il s'est connecté {entrees}."
    elif det.suspectes:
        phrase2 = ("Aucune connexion n'a réussi depuis ces sources : "
                   "l'attaquant n'est pas entré dans le système.")
    else:
        phrase2 = "Aucune connexion d'un attaquant n'a donc été constatée."

    faits = []
    for ch in inv.chronos:
        for q in ch.evenements:
            d = q.evt.details
            if q.nature == "processus_suspect":
                faits.append(f"exécuté une commande suspecte sur {q.evt.host}")
            elif q.nature == "tache_planifiee":
                faits.append(f"programmé la tâche {d.get('task_name') or 'inconnue'} "
                             f"pour revenir plus tard")
            elif q.nature == "creation_compte":
                faits.append(f"créé le compte {d.get('new_account') or 'inconnu'}")
            elif q.nature == "ajout_groupe_privilegie":
                faits.append(f"donné à {d.get('member') or 'un compte'} les droits "
                             f"d'administration ({d.get('group') or 'groupe à privilèges'})")
            elif q.nature == "mouvement_lateral":
                faits.append(f"rebondi vers la machine {q.evt.host}")
            elif q.nature == "effacement_journal":
                faits.append(f"effacé le journal de sécurité de {q.evt.host}")
    faits = list(dict.fromkeys(faits))
    gravite = inv.gravite.lower()
    if faits:
        phrase3 = (f"Une fois entré, l'attaquant a {_enumerer(faits)} ; "
                   f"la gravité est jugée {gravite}.")
    else:
        phrase3 = (f"La gravité est jugée {gravite} : "
                   f"{_justifier_gravite(inv.gravite, piv, inv.chronos)}.")
    return [phrase1, phrase2, phrase3]


def construire_donnees_rapport(inv: Investigation, genere_le: datetime) -> dict:
    """Données du rapport PDF, déjà rédigées : rapport_pdf ne fait que la mise en page."""
    def h(dt):
        return formater_heure(dt, inv.multi_jours)

    etapes = []
    for texte in _explications(inv):
        titre, _, corps = texte.partition("\n")
        etapes.append({"titre": titre.strip("= ").strip(), "texte": corps})

    vus, chronologie = set(), []
    for ch in inv.chronos:
        for q in ch.evenements:
            if id(q.evt) in vus:   # un même événement peut figurer dans plusieurs chronologies
                continue
            vus.add(id(q.evt))
            chronologie.append((q.evt.timestamp, [
                h(q.evt.timestamp), q.evt.host, q.evt.account,
                ("[!] " if q.suspect else "") + q.description]))
    chronologie.sort(key=lambda x: x[0])

    return {
        "titre": "Rapport d'incident de sécurité",
        "fichier": os.path.basename(inv.chemin),
        "nb_evenements": len(inv.evts),
        "periode": _periode(inv, " au "),
        "gravite": inv.gravite,
        "synthese": _synthese(inv),
        "actions_prioritaires": [a.action for a in inv.actions if a.priorite == PRIORITES[0]],
        "etapes": etapes,
        "chronologie": [ligne for _, ligne in chronologie],
        "plan": [[a.fait, a.action, a.priorite] for a in inv.actions],
        "iocs": [[i.valeur, _libelle_ioc(i),
                  _verdict_vt(i) if i.statut_enrichissement else "non vérifié"]
                 for i in inv.iocs],
        "details_vt": [{"valeur": i.valeur, "libelle": _libelle_ioc(i),
                        "lignes": _lignes_detail_vt(i)}
                       for i in inv.iocs if _lignes_detail_vt(i)],
        "genere_le": f"{genere_le.astimezone(timezone.utc):%d/%m/%Y à %H:%M} UTC",
    }


def _valide_depuis(inv: Investigation, genere_le: datetime) -> datetime:
    """Début de validité STIX : première IP suspecte, sinon premier événement."""
    if inv.det.suspectes:
        return inv.det.suspectes[0].debut
    if inv.evts:
        return inv.evts[0].timestamp
    return genere_le


def _chemin_logo() -> str | None:
    """Chemin du logo (relatif au dossier du script s'il n'est pas absolu), None si absent."""
    chemin = LOGO if os.path.isabs(LOGO) else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), LOGO)
    return chemin if os.path.isfile(chemin) else None


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : rapport sur la sortie standard et fichiers dans le dossier courant."""
    parseur = argparse.ArgumentParser(
        description="Investigation chaînée automatisée de logs de sécurité Windows.")
    parseur.add_argument("chemin", nargs="?", default=FICHIER_LOGS,
                         help=f"fichier JSON de logs (défaut : {FICHIER_LOGS})")
    parseur.add_argument("--enrichir", action="store_true",
                         help="interroger VirusTotal (clé dans VT_API_KEY)")
    parseur.add_argument("--pdf", action="store_true",
                         help="produire aussi le rapport PDF (le rapport Word est toujours produit)")
    args = parseur.parse_args(argv)

    if args.enrichir:
        print(f"Enrichissement VirusTotal : au moins {VT_INTERVALLE_S} s entre deux "
              f"requêtes, cela peut prendre quelques minutes.", file=sys.stderr)
    try:
        inv = investiguer(args.chemin, enrichir=args.enrichir)
    except ErreurChargement as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1

    texte = rapport_texte(inv)
    print(texte, end="")
    genere_le = datetime.now(timezone.utc)
    try:
        with open(SORTIE_TXT, "w", encoding="utf-8") as f:
            f.write(texte)
        exporter_misp_csv(inv.iocs, SORTIE_MISP)
        exporter_stix(inv.iocs, SORTIE_STIX, genere_le, _valide_depuis(inv, genere_le))
        produits = [SORTIE_TXT, SORTIE_MISP, SORTIE_STIX]
        donnees = construire_donnees_rapport(inv, genere_le)
        erreurs = False
        try:
            from rapport_word import generer_docx
        except ImportError:
            print("\nRapport Word non généré : python-docx absent "
                  "(pip/apt install python-docx)")
        else:
            logo = _chemin_logo()
            if logo is None:
                print(f"Avertissement : logo introuvable ({LOGO}), page de garde sans logo.",
                      file=sys.stderr)
            try:
                generer_docx(SORTIE_DOCX, donnees, logo)
                produits.append(SORTIE_DOCX)
            except OSError:
                raise
            except Exception as exc:  # mise en page impossible
                print(f"Erreur : rapport Word non généré : {type(exc).__name__} : "
                      f"{str(exc)[:300]}", file=sys.stderr)
                erreurs = True
        if args.pdf:
            try:
                from rapport_pdf import generer_pdf
            except ImportError:
                print("\nPDF non généré : reportlab absent (pip/apt install reportlab)")
            else:
                try:
                    generer_pdf(SORTIE_PDF, donnees)
                    produits.append(SORTIE_PDF)
                except OSError:
                    raise
                except Exception as exc:  # mise en page impossible (LayoutError de reportlab…)
                    print(f"Erreur : PDF non généré : {type(exc).__name__} : "
                          f"{str(exc)[:300]}", file=sys.stderr)
                    erreurs = True
    except OSError as exc:
        print(f"Erreur : écriture des fichiers de sortie impossible ({exc})", file=sys.stderr)
        return 1
    print(f"\nFichiers produits : {', '.join(produits)}")
    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(main())
