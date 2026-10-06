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
import base64
import binascii
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import ntpath
import re

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
    for e in evts:
        if e.event_id != EVT_ECHEC or not e.src_ip:
            continue
        total += 1
        par_ip[e.src_ip].append(e)
        if e.result == "success":
            incoherences += 1

    suspectes, ecartees = [], []
    for ip, liste in par_ip.items():
        comptes = sorted({e.account for e in liste})
        categorie, motif = _classer(ip, len(liste), len(comptes),
                                    seuil_echecs, seuil_comptes)
        profil = ProfilIP(
            ip=ip, nb_echecs=len(liste), comptes=comptes,
            hosts=sorted({e.host for e in liste}),
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
                             seuil_echecs, seuil_comptes)


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
        f"Résultat : {det.nb_echecs_total} échecs de connexion analysés, venant de "
        f"{_pl(det.nb_ip_analysees, 'adresse IP', 'adresses IP')} ; "
        f"{_pl(len(det.suspectes), 'suspecte', 'suspectes')}.")
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
                couples.setdefault((e.account, e.host), e)
        if not couples:
            non_abouties.append(profil)
        for (compte, host), e in couples.items():
            compromissions.append(Compromission(
                profil.ip, compte, host, e.timestamp, e.logon_type, profil))
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
        "survenues après son premier échec, c'est-à-dire un compte deviné par l'attaquant.")
    lignes.append(
        f"Résultat : {_pl(len(piv.compromissions), 'compromission', 'compromissions')} "
        f"; {_pl(len(piv.non_abouties), 'IP suspecte', 'IP suspectes')} sans connexion réussie.")
    for c in piv.compromissions:
        mode = _TYPES_CONNEXION.get(c.logon_type, "de type inconnu")
        lignes.append(
            f"  - L'attaque depuis {c.ip} a abouti : le compte {c.compte} s'est connecté à "
            f"{c.host} à {formater_heure(c.t0, multi_jours)}, {mode}.")
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
    nature: str  # connexion_initiale | connexion | mouvement_lateral | processus_suspect |
    #              processus_benin | tache_planifiee | creation_compte | ajout_groupe |
    #              ajout_groupe_privilegie | effacement_journal | autre
    description: str
    suspect: bool
    commande_decodee: str | None = None


@dataclass
class Chronologie:
    """Activité post-compromission pour une compromission."""
    compromission: Compromission
    evenements: list[EvenementQualifie]
    comptes_suivis: list[str]   # compte compromis, puis comptes créés par l'attaquant


_OPTIONS_ENCODEES = {"-enc", "-encodedcommand", "-e"}


def decoder_commande(ligne: str) -> str | None:
    """Décode l'argument encodé (-enc / -encodedcommand / -e) d'une ligne de commande.

    None s'il n'y a pas de paramètre encodé ; "non décodable" si le décodage
    base64 puis UTF-16LE échoue ou si l'argument manque.
    """
    mots = (ligne or "").split()
    for i, mot in enumerate(mots):
        if mot.lower() in _OPTIONS_ENCODEES:
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


def _marqueurs_presents(ligne: str) -> bool:
    """Vrai si un marqueur suspect figure comme mot entier parmi les arguments.

    L'exécutable (premier mot) est ignoré : iexplore.exe ou un chemin contenant
    « hidden » ne comptent pas, pas plus que -nopause pour -nop.
    """
    mots = ligne.split(None, 1)
    if mots and mots[0].lower().strip('"').endswith(_EXTENSIONS_EXE):
        ligne = mots[1] if len(mots) > 1 else ""
    jetons = {j for j in _SEPARATEURS.split(ligne.lower()) if j}
    return any(m in jetons for m in MARQUEURS_CMD_SUSPECTS)


def qualifier_evenement(e: Evenement, c: Compromission) -> EvenementQualifie:
    """Qualifie un événement du périmètre de la compromission c."""
    d = e.details
    if e.event_id == EVT_SUCCES:
        if e.timestamp == c.t0 and e.host == c.host and e.account == c.compte:
            return EvenementQualifie(
                e, "connexion_initiale",
                f"connexion de {e.account} depuis {e.src_ip or 'IP inconnue'} "
                f"(début de la compromission)", True)
        if e.host != c.host:
            return EvenementQualifie(
                e, "mouvement_lateral",
                f"connexion de {e.account} sur {e.host} depuis "
                f"{e.src_ip or 'IP inconnue'} (mouvement latéral)", True)
        return EvenementQualifie(
            e, "connexion",
            f"connexion de {e.account} depuis {e.src_ip or 'IP inconnue'}", False)
    if e.event_id == EVT_PROCESSUS:
        processus = _nom_processus(d.get("process"))
        parent = _nom_processus(d.get("parent_process"))
        ligne = str(d.get("command_line") or "")
        office = parent in PARENTS_BUREAUTIQUES and processus in INTERPRETEURS
        marqueur = _marqueurs_presents(ligne)
        if office or marqueur:
            decodee = decoder_commande(ligne)
            motif = (f"lancé par {parent}" if office else "avec des options suspectes")
            desc = f"{processus or 'processus inconnu'} {motif} (exécution suspecte) : {ligne}"
            if decodee is not None:
                desc += f" ; commande décodée : {decodee} (commande encodée, contenu masqué)"
            if re.search(r"https?://", ligne, re.IGNORECASE):
                desc += " (téléchargement d'un fichier depuis Internet)"
            return EvenementQualifie(e, "processus_suspect", desc, True, decodee)
        return EvenementQualifie(
            e, "processus_benin",
            f"processus {processus or 'inconnu'} lancé par {parent or 'inconnu'} (sans anomalie)",
            False)
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
    compte créé (4720) dans le périmètre est suivi à son tour.
    """
    chronos = []
    for c in piv.compromissions:
        suivis = [c.compte]
        retenus = []
        for e in evts:  # trié chronologiquement
            if e.timestamp < c.t0 or e.event_id == EVT_ECHEC:
                continue
            membre = e.details.get("member") if e.event_id == EVT_AJOUT_GROUPE else None
            if e.host == c.host or e.account in suivis or membre in suivis:
                retenus.append(qualifier_evenement(e, c))
                if e.event_id == EVT_CREATION_COMPTE:
                    nouveau = e.details.get("new_account")
                    if nouveau and nouveau not in suivis:
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
