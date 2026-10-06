"""Extraction des IOC et exports MISP (CSV) / STIX 2.1 (JSON écrit à la main).

Ce module ne dépend pas d'`investigation` : les résultats des étapes 1 à 3
sont consommés par duck typing.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import uuid
from urllib.parse import urlsplit
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

EXTENSIONS_FICHIERS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "txt", "dat",
                       "tmp", "log", "lnk", "zip", "msi", "doc", "docx", "xls", "xlsx",
                       "ppt", "pptx", "pdf", "sys"}

# Dernier label accepté pour un domaine trouvé « nu » dans un texte. Compromis
# assumé : la stdlib n'a pas de liste des suffixes publics, et sans filtre les
# noms de comptes (a.durand) ou de classes .NET (Net.WebClient) ressortiraient
# comme domaines à to_ids=1. Un domaine extrait d'une URL est toujours conservé.
TLD_CONNUS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "site", "online",
    "club", "shop", "app", "dev", "cloud", "live", "pro", "tech", "store", "link", "click",
    "icu", "vip", "work", "fun", "space", "website", "page", "name", "mobi", "edu", "gov",
    "ru", "cn", "fr", "de", "uk", "us", "eu", "nl", "be", "ch", "es", "it", "pl", "br",
    "in", "jp", "kr", "ir", "kp", "tk", "ml", "ga", "cf", "gq", "su", "ua", "by", "kz",
    "tr", "vn", "id", "th", "cc", "tv", "ws", "pw", "ca", "au", "se", "no", "fi", "dk",
    "cz", "ro", "hk", "tw", "sg", "za", "mx", "ar",
}

# Champs d'identifiants : jamais analysés pour y chercher des domaines.
CHAMPS_IDENTIFIANTS = {"task_name", "new_account", "member", "group"}

# Le STIX 2.1 (§2.9) recommande, pour les SCO, un UUIDv5 dérivé des propriétés
# contributrices avec son espace de noms fixe (00abedb4-aa42-466c-9c01-fed23315a9b7) ;
# on garde ici notre espace de noms (identifiants stables, suffisants pour OpenCTI).
NAMESPACE_STIX = uuid.uuid5(uuid.NAMESPACE_URL, "forcert-investigation-automatisee")
AUTEUR_STIX = "ForCERT - investigation automatisée"
NOM_RAPPORT = "Incident - investigation automatisée"
ABSENT = "non décodable"


@dataclass
class IOC:
    valeur: str
    type_misp: str
    categorie_misp: str
    to_ids: bool
    commentaire: str
    statut_enrichissement: str | None = None
    enrichissement: dict | None = None
    # ip_attaque | reseau | hash | compte_cree | tache | commande | compte_compromis | machine
    role: str = ""


# --- Motifs ---------------------------------------------------------------

_RE_HASH = [("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
            ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
            ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b"))]
_RE_URL = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_RE_DOMAINE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?![\w-])",
    re.IGNORECASE)
_RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")


def extraire_motifs(texte: str) -> list[tuple[str, str]]:
    """Renvoie les (type_misp, valeur) trouvés dans texte, sans doublon, dans l'ordre."""
    trouves: list[tuple[str, str]] = []

    def ajouter(t, v):
        if (t, v) not in trouves:
            trouves.append((t, v))

    texte = texte or ""
    for type_misp, motif in _RE_HASH:
        for m in motif.finditer(texte):
            ajouter(type_misp, m.group(0).lower())
    for m in _RE_URL.finditer(texte):
        ajouter("url", m.group(0).rstrip(".,;:)]}"))
    for m in _RE_URL.finditer(texte):  # hôte d'URL : conservé quel que soit le TLD
        try:
            hote = urlsplit(m.group(0).rstrip(".,;:)]}")).hostname or ""
        except ValueError:  # ex. « http://[::1/x » : on garde l'URL (IOC), sans en déduire d'hôte
            hote = ""
        if hote and not _RE_IPV4.fullmatch(hote) and ":" not in hote:
            ajouter("domain", hote.lower())
    for m in _RE_DOMAINE.finditer(texte):
        tld = m.group(1).lower()
        if tld in TLD_CONNUS and tld not in EXTENSIONS_FICHIERS:
            ajouter("domain", m.group(0).lower())
    for m in _RE_IPV4.finditer(texte):
        try:
            ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        ajouter("ip-dst", m.group(0))
    return trouves


# --- Extraction -----------------------------------------------------------

def _hm(dt: datetime, jour: bool = False) -> str:
    return dt.strftime("%d/%m %H:%M" if jour else "%H:%M")


def _pl(n: int, sing: str, plur: str) -> str:
    return sing if n == 1 else plur


def _commentaire_ip(p, multi_jours: bool = False) -> str:
    libelle = {"spraying": "du password spraying", "force_brute": "de la force brute"}.get(
        p.categorie, "d'une activité d'échecs d'authentification")
    n = p.nb_echecs
    c = len(p.comptes)
    fin = getattr(p, "fin", None) or p.debut
    jour = multi_jours or fin.date() != p.debut.date()
    return (f"IP source {libelle} ({n} {_pl(n, 'échec', 'échecs')} sur "
            f"{c} {_pl(c, 'compte', 'comptes')}, {_hm(p.debut, jour)}–{_hm(fin, jour)})")


RESEAUX_PRIVES = [ipaddress.ip_network(r)
                  for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _est_prive(ip: str) -> bool:
    """Vérification RFC 1918 par défaut (l'appelant peut fournir la sienne)."""
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(adresse in r for r in RESEAUX_PRIVES if adresse.version == r.version)


def extraire_iocs(det, piv, chronos, est_interne: Callable[[str], bool] | None = None,
                  multi_jours: bool = False) -> list[IOC]:
    """Construit la liste dédoublonnée (type_misp, valeur) des IOC, premier commentaire gardé.

    Les motifs réseau et empreintes ne sont cherchés que dans les événements
    suspects ; une IP interne (est_interne, RFC 1918 par défaut) n'est jamais
    publiée comme IP de destination. multi_jours : dates dans les commentaires.
    """
    est_interne = est_interne or _est_prive
    iocs: list[IOC] = []
    vus: set[tuple[str, str]] = set()

    def ajouter(valeur, type_misp, categorie, to_ids, commentaire, role):
        if not valeur or (type_misp, valeur) in vus:
            return
        if type_misp == "ip-dst" and ("ip-src", valeur) in vus:
            return  # IP d'attaque déjà connue : on ne la republie pas comme destination
        vus.add((type_misp, valeur))
        iocs.append(IOC(valeur, type_misp, categorie, to_ids, commentaire, role=role))

    for p in det.suspectes:
        ajouter(p.ip, "ip-src", "Network activity", True, _commentaire_ip(p, multi_jours), "ip_attaque")

    for c in piv.compromissions:
        ajouter(c.compte, "target-user", "Targeting data", False,
                f"Compte compromis par {c.ip} sur {c.host} à {_hm(c.t0, multi_jours)}",
                "compte_compromis")
        ajouter(c.host, "target-machine", "Targeting data", False,
                f"Machine compromise : connexion réussie de {c.compte} depuis {c.ip} "
                f"à {_hm(c.t0, multi_jours)}", "machine")

    for ch in chronos:
        for q in ch.evenements:
            e = q.evt
            d = e.details
            heure = _hm(e.timestamp, multi_jours)
            if q.nature == "mouvement_lateral":
                ajouter(e.host, "target-machine", "Targeting data", False,
                        f"Machine touchée par mouvement latéral : connexion de {e.account} "
                        f"à {heure}", "machine")
            elif q.nature == "creation_compte":
                ajouter(d.get("new_account"), "text", "Persistence mechanism", False,
                        f"Compte créé par l'attaquant sur {e.host} à {heure}", "compte_cree")
            elif q.nature == "tache_planifiee":
                ajouter(d.get("task_name"), "text", "Persistence mechanism", False,
                        f"Tâche planifiée créée par {e.account} sur {e.host} à {heure}", "tache")
            elif q.nature == "processus_suspect":
                ligne = d.get("command_line")
                if ligne:
                    ajouter(str(ligne), "text", "Payload installation", False,
                            f"Ligne de commande suspecte exécutée par {e.account} sur "
                            f"{e.host} à {heure}", "commande")

            # Motifs : valeurs texte de details + commande décodée, pour les seuls
            # événements suspects (pas l'activité normale d'autres utilisateurs).
            if not getattr(q, "suspect", False):
                continue
            sources = [(k, v) for k, v in d.items() if isinstance(v, str)]
            if q.commande_decodee and q.commande_decodee != ABSENT:
                sources.append(("commande décodée", q.commande_decodee))
            for cle, texte in sources:
                origine = "la commande décodée" if cle == "commande décodée" else f"le champ {cle}"
                for type_misp, valeur in extraire_motifs(texte):
                    if type_misp == "domain" and cle in CHAMPS_IDENTIFIANTS:
                        continue
                    lieu = f"{origine} de {e.account or 'compte inconnu'} sur {e.host} à {heure}"
                    if type_misp in ("md5", "sha1", "sha256"):
                        ajouter(valeur, type_misp, "Payload delivery", True,
                                f"Empreinte {type_misp.upper()} observée dans {lieu}", "hash")
                    else:
                        if type_misp == "ip-dst" and est_interne(valeur):
                            continue
                        nom = {"url": "URL", "domain": "Domaine", "ip-dst": "IP de destination"}[type_misp]
                        ajouter(valeur, type_misp, "Network activity", True,
                                f"{nom} observé(e) dans {lieu}", "reseau")
    return iocs


# --- Export MISP ----------------------------------------------------------

def exporter_misp_csv(iocs: list[IOC], chemin: str) -> None:
    """Un fichier = un événement MISP ; to_ids en 1/0, verdict VT ajouté au commentaire."""
    with open(chemin, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["value", "type", "category", "to_ids", "comment"])
        for i in iocs:
            commentaire = i.commentaire
            if i.statut_enrichissement:
                commentaire += f" | VT : {i.statut_enrichissement}"
            w.writerow([i.valeur, i.type_misp, i.categorie_misp, 1 if i.to_ids else 0,
                        commentaire])


# --- Export STIX 2.1 ------------------------------------------------------

def _ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(type_stix: str, cle: str) -> str:
    return f"{type_stix}--{uuid.uuid5(NAMESPACE_STIX, f'{type_stix}:{cle}')}"


def _echapper(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(type_misp: str, valeur: str) -> str | None:
    v = _echapper(valeur)
    if type_misp in ("ip-src", "ip-dst"):
        objet = "ipv6-addr" if ":" in valeur else "ipv4-addr"
        return f"[{objet}:value = '{v}']"
    return {"domain": f"[domain-name:value = '{v}']",
            "url": f"[url:value = '{v}']",
            "md5": f"[file:hashes.MD5 = '{v}']",
            "sha1": f"[file:hashes.'SHA-1' = '{v}']",
            "sha256": f"[file:hashes.'SHA-256' = '{v}']"}.get(type_misp)


def exporter_stix(iocs: list[IOC], chemin: str, genere_le: datetime,
                  valide_depuis: datetime) -> dict:
    """Écrit et renvoie le bundle STIX 2.1.

    Indicators pour IP/domaine/URL/hash, user-account pour les comptes compromis
    et créés. Les noms de tâches et lignes de commande ne sont pas exportés en
    STIX (ils n'ont pas d'objet STIX naturel) : ils restent propres à l'export MISP.
    """
    cree = _ts(genere_le)
    identite = {"type": "identity", "spec_version": "2.1", "id": _id("identity", AUTEUR_STIX),
                "created": cree, "modified": cree, "name": AUTEUR_STIX,
                "identity_class": "organization"}
    objets = []
    comptes_vus = set()
    for i in iocs:
        pattern = _pattern(i.type_misp, i.valeur)
        if pattern:
            objets.append({
                "type": "indicator", "spec_version": "2.1",
                "id": _id("indicator", f"{i.type_misp}:{i.valeur}"),
                "created": cree, "modified": cree, "created_by_ref": identite["id"],
                "name": f"{i.type_misp} : {i.valeur}", "description": i.commentaire,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern, "pattern_type": "stix",
                "valid_from": _ts(valide_depuis)})
        elif (i.type_misp == "target-user" or i.role == "compte_cree") \
                and i.valeur not in comptes_vus:
            comptes_vus.add(i.valeur)
            objets.append({"type": "user-account", "spec_version": "2.1",
                           "id": _id("user-account", i.valeur), "user_id": i.valeur})
    cle_rapport = "|".join(sorted(f"{i.type_misp}:{i.valeur}" for i in iocs))
    refs = [o["id"] for o in objets] or [identite["id"]]  # object_refs ne peut pas être vide
    rapport = {"type": "report", "spec_version": "2.1", "id": _id("report", cle_rapport),
               "created": cree, "modified": cree, "created_by_ref": identite["id"],
               "name": NOM_RAPPORT, "report_types": ["incident"], "published": cree,
               "object_refs": refs}
    bundle = {"type": "bundle", "id": _id("bundle", cle_rapport),
              "objects": [identite, *objets, rapport]}
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    return bundle
