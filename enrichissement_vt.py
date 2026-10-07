"""Enrichissement VirusTotal (API v3) : consultation seule, jamais d'upload.

Module autonome (stdlib uniquement) : interrogation en direct à chaque
exécution (une même valeur n'est demandée qu'une fois par exécution), cache
disque optionnel (désactivé si chemin_cache vaut None), limitation de débit,
retry sur 429, arrêt propre sur clé refusée.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

VT_URL = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui"
MAX_MOTEURS = 15  # moteurs détaillés au plus ; le total reste dans nb_moteurs_signales

TYPES_VT = {
    "ip-src": "ip_addresses", "ip-dst": "ip_addresses",
    "domain": "domains", "url": "urls",
    "md5": "files", "sha1": "files", "sha256": "files",
}

RESEAUX_DOCUMENTATION = [ipaddress.ip_network(n) for n in
                         ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@dataclass
class ResultatVT:
    # statut : ok, inconnu, non_soumis, non_applicable, cle_absente,
    # cle_invalide, indisponible
    statut: str
    donnees: dict | None = None
    message: str = ""


class ClientVT:
    def __init__(self, cle, chemin_cache, ttl_heures=24, intervalle_s=15,
                 timeout_s=10, max_essais=3, urlopen=urllib.request.urlopen,
                 horloge=time.time, dormir=time.sleep):
        self.cle = cle
        self.chemin_cache = chemin_cache
        self.ttl_s = ttl_heures * 3600
        self.intervalle_s = intervalle_s
        self.timeout_s = timeout_s
        self.max_essais = max_essais
        self._urlopen = urlopen
        self._horloge = horloge
        self._dormir = dormir
        self._dernier = None  # instant de la dernière requête réelle
        self._desactive = False
        self._cache = self._charger_cache()

    # --- cache -----------------------------------------------------------
    def _charger_cache(self):
        # Sans fichier de cache : mémoire seule, vidée à chaque exécution.
        if self.chemin_cache is None:
            return {}
        try:
            with open(self.chemin_cache, encoding="utf-8") as f:
                cache = json.load(f)
            return cache if isinstance(cache, dict) else {}
        except (OSError, ValueError):
            return {}

    def _ecrire_cache(self):
        if self.chemin_cache is None:
            return
        tmp = self.chemin_cache + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False)
            os.replace(tmp, self.chemin_cache)
        except OSError as e:
            print(f"Avertissement : cache VirusTotal non écrit ({e.strerror}).",
                  file=sys.stderr)

    def _depuis_cache(self, cle_cache):
        e = self._cache.get(cle_cache)
        if not isinstance(e, dict):
            return None
        try:
            if self._horloge() - float(e["horodatage"]) >= self.ttl_s:
                return None
            statut, donnees = e["statut"], e.get("donnees")
        except (KeyError, TypeError, ValueError):
            return None
        message = "inconnu de VirusTotal" if statut == "inconnu" else ""
        return ResultatVT(statut, donnees, message)

    # --- API -------------------------------------------------------------
    @staticmethod
    def _non_soumise(valeur):
        try:
            ip = ipaddress.ip_address(valeur)
        except ValueError:
            return None  # pas une IP valide : laissée à VT
        if ip.is_global:
            return None
        if any(ip in r for r in RESEAUX_DOCUMENTATION if ip.version == r.version):
            return "plage de documentation RFC 5737, non soumise"
        return "adresse non routable, non soumise"

    @staticmethod
    def _identifiant(type_misp, valeur):
        if type_misp == "url":
            return base64.urlsafe_b64encode(valeur.encode()).decode().rstrip("=")
        return urllib.parse.quote(valeur, safe="")

    def _attendre_intervalle(self):
        if self._dernier is not None:
            ecoule = self._horloge() - self._dernier
            if ecoule < self.intervalle_s:
                self._dormir(self.intervalle_s - ecoule)

    @staticmethod
    def _extraire(corps):
        attrs = json.loads(corps)["data"]["attributes"]
        donnees = dict(attrs.get("last_analysis_stats") or {})
        for champ in ("reputation", "country", "as_owner", "last_analysis_date"):
            donnees[champ] = attrs.get(champ)
        # Détails complémentaires : conservés seulement s'ils sont présents
        for champ in ("asn", "network", "continent", "regional_internet_registry",
                      "tags", "total_votes", "categories", "type_description",
                      "meaningful_name"):
            if attrs.get(champ) not in (None, "", [], {}):
                donnees[champ] = attrs[champ]
        # Moteurs ayant signalé l'objet (malveillant ou suspect), triés, plafonnés à 15
        signales = sorted(
            ({"moteur": nom, "categorie": r.get("category"), "resultat": r.get("result")}
             for nom, r in (attrs.get("last_analysis_results") or {}).items()
             if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")),
            key=lambda m: m["moteur"])
        if signales:
            donnees["moteurs"] = signales[:MAX_MOTEURS]
            donnees["nb_moteurs_signales"] = len(signales)
        return donnees

    @staticmethod
    def _lien(type_misp, valeur):
        """Fiche de l'objet dans l'interface web VirusTotal."""
        if type_misp in ("ip-src", "ip-dst"):
            return f"{VT_GUI}/ip-address/{valeur}"
        if type_misp == "domain":
            return f"{VT_GUI}/domain/{valeur}"
        if type_misp == "url":
            return f"{VT_GUI}/url/{ClientVT._identifiant('url', valeur)}"
        return f"{VT_GUI}/file/{valeur}"

    def consulter(self, type_misp, valeur):
        if type_misp not in TYPES_VT:
            return ResultatVT("non_applicable", None, "type non pris en charge par VirusTotal")
        if type_misp in ("ip-src", "ip-dst"):
            motif = self._non_soumise(valeur)
            if motif:
                return ResultatVT("non_soumis", None, motif)
        # Clé invalide : prioritaire sur le cache, l'enrichissement est arrêté net.
        if self._desactive:
            return ResultatVT("cle_invalide", None, "clé refusée par VirusTotal (401)")
        if not self.cle:
            return ResultatVT("cle_absente", None,
                              "clé VT_API_KEY absente : enrichissement non effectué")
        cle_cache = f"{type_misp}:{valeur}"
        en_cache = self._depuis_cache(cle_cache)
        if en_cache is not None:
            return en_cache

        url = f"{VT_URL}/{TYPES_VT[type_misp]}/{self._identifiant(type_misp, valeur)}"
        dernier_code = None
        for essai in range(self.max_essais):
            self._attendre_intervalle()
            req = urllib.request.Request(
                url, headers={"x-apikey": self.cle, "Accept": "application/json"})
            self._dernier = self._horloge()
            try:
                with self._urlopen(req, timeout=self.timeout_s) as rep:
                    corps = rep.read()
                donnees = self._extraire(corps)
                donnees["lien"] = self._lien(type_misp, valeur)
                resultat = ResultatVT("ok", donnees)
                return self._memoriser(cle_cache, resultat)
            except urllib.error.HTTPError as e:
                e.close()  # libère la réponse d'erreur
                dernier_code = e.code
                if e.code == 404:
                    return self._memoriser(
                        cle_cache, ResultatVT("inconnu", None, "inconnu de VirusTotal"))
                if e.code in (401, 403):
                    self._desactive = True
                    return ResultatVT("cle_invalide", None,
                                      f"clé refusée par VirusTotal ({e.code})")
                if e.code == 429:
                    if essai < self.max_essais - 1:
                        self._dormir(self.intervalle_s * 2 ** essai)
                    continue
                return ResultatVT("indisponible", None, f"VirusTotal indisponible (HTTP {e.code})")
            except TimeoutError:
                return ResultatVT("indisponible", None, "délai dépassé")
            except urllib.error.URLError as e:
                return ResultatVT("indisponible", None, f"VirusTotal injoignable ({e.reason})")
            except (ValueError, KeyError, TypeError):
                return ResultatVT("indisponible", None, "réponse VirusTotal illisible")
        return ResultatVT("indisponible", None,
                          f"VirusTotal indisponible après {self.max_essais} essais ({dernier_code})")

    def _memoriser(self, cle_cache, resultat):
        self._cache[cle_cache] = {"horodatage": self._horloge(),
                                  "statut": resultat.statut,
                                  "donnees": resultat.donnees}
        self._ecrire_cache()
        return resultat


def enrichir_iocs(iocs, client):
    """Renseigne statut_enrichissement et enrichissement de chaque IOC.

    enrichissement = donnees VT si présentes ; sinon, pour un statut != "ok",
    {"message": message} afin que le rapport puisse expliquer l'absence de verdict.
    Renvoie le comptage par statut.
    """
    compte = {}
    for ioc in iocs:
        r = client.consulter(ioc.type_misp, ioc.valeur)
        ioc.statut_enrichissement = r.statut
        if r.donnees is not None:
            ioc.enrichissement = r.donnees
        elif r.statut != "ok" and r.message:
            ioc.enrichissement = {"message": r.message}
        else:
            ioc.enrichissement = None
        compte[r.statut] = compte.get(r.statut, 0) + 1
    return compte
