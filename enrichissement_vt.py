"""Enrichissement VirusTotal (API v3) : consultation seule, jamais d'upload.

Module autonome (stdlib uniquement) : cache disque, limitation de débit,
retry sur 429, arrêt propre sur clé refusée.
"""
import base64
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

VT_URL = "https://www.virustotal.com/api/v3"

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
        try:
            with open(self.chemin_cache, encoding="utf-8") as f:
                cache = json.load(f)
            return cache if isinstance(cache, dict) else {}
        except (OSError, ValueError):
            return {}

    def _ecrire_cache(self):
        tmp = self.chemin_cache + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False)
            os.replace(tmp, self.chemin_cache)
        except OSError:
            pass  # cache non critique

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
        return valeur

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
        return donnees

    def consulter(self, type_misp, valeur):
        if type_misp not in TYPES_VT:
            return ResultatVT("non_applicable", None, "type non pris en charge par VirusTotal")
        if type_misp in ("ip-src", "ip-dst"):
            motif = self._non_soumise(valeur)
            if motif:
                return ResultatVT("non_soumis", None, motif)
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
                resultat = ResultatVT("ok", self._extraire(corps))
                return self._memoriser(cle_cache, resultat)
            except urllib.error.HTTPError as e:
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
