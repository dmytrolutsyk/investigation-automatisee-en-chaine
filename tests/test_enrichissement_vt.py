import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error

from enrichissement_vt import ClientVT, ResultatVT, enrichir_iocs
from iocs import IOC


class Reponse:
    def __init__(self, corps):
        self._corps = corps

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._corps


def ok_json(**attrs):
    stats = {"malicious": 3, "suspicious": 1, "harmless": 50, "undetected": 10}
    a = {"last_analysis_stats": stats, "country": "NL", "reputation": -5,
         "as_owner": "ACME", "last_analysis_date": 1700000000}
    a.update(attrs)
    return Reponse(json.dumps({"data": {"attributes": a}}).encode())


def http(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b""))


class Base(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dossier, True)
        self.cache = os.path.join(self.dossier, "cache.json")
        self.appels = []
        self.sommeils = []
        self.t = [1000.0]
        self.reponses = []

    def urlopen(self, req, timeout=None):
        self.appels.append(req)
        self.timeout = timeout
        r = self.reponses.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r

    def client(self, cle="K", **kw):
        return ClientVT(cle, self.cache, urlopen=self.urlopen,
                        horloge=lambda: self.t[0],
                        dormir=self.sommeils.append, **kw)


class TestClientVT(Base):
    def test_succes(self):
        self.reponses = [ok_json()]
        r = self.client().consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, r.donnees["malicious"]), ("ok", 3))
        self.assertEqual(r.donnees["country"], "NL")
        self.assertIn("/ip_addresses/8.8.4.4", self.appels[0].full_url)
        self.assertEqual(self.appels[0].get_method(), "GET")
        self.assertEqual(self.appels[0].get_header("X-apikey"), "K")
        self.assertEqual(self.timeout, 10)

    def test_url_base64(self):
        self.reponses = [ok_json()]
        self.client().consulter("url", "http://a.b/c")
        self.assertTrue(self.appels[0].full_url.endswith("/urls/aHR0cDovL2EuYi9j"))

    def test_inconnu_404(self):
        self.reponses = [http(404)]
        r = self.client().consulter("domain", "exemple.org")
        self.assertEqual(r.statut, "inconnu")
        self.assertIn("inconnu", r.message)

    def test_429_puis_succes(self):
        self.reponses = [http(429), ok_json()]
        r = self.client().consulter("sha256", "ab" * 32)
        self.assertEqual((r.statut, len(self.appels)), ("ok", 2))
        self.assertIn(15, self.sommeils)

    def test_429_persistant(self):
        self.reponses = [http(429)] * 3
        r = self.client().consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels)), ("indisponible", 3))
        self.assertIn("429", r.message)

    def test_401_desactive(self):
        self.reponses = [http(401)]
        c = self.client()
        r1 = c.consulter("ip-src", "8.8.4.4")
        r2 = c.consulter("ip-src", "8.8.8.8")
        self.assertEqual((r1.statut, r2.statut), ("cle_invalide", "cle_invalide"))
        self.assertEqual(len(self.appels), 1)

    def test_403_cle_invalide(self):
        self.reponses = [http(403)]
        r = self.client().consulter("ip-src", "8.8.4.4")
        self.assertEqual(r.statut, "cle_invalide")
        self.assertIn("403", r.message)

    def test_500_indisponible(self):
        self.reponses = [http(500)]
        r = self.client().consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels)), ("indisponible", 1))

    def test_backoff_429(self):
        self.reponses = [http(429)] * 3
        self.client().consulter("ip-src", "8.8.4.4")
        # horloge figée : attente d'intervalle avant les essais 2 et 3,
        # backoff 15 puis 30 après les 429 (pas d'attente après le dernier)
        self.assertEqual(self.sommeils, [15, 15, 30, 15])

    def test_cache_sans_cle_api(self):
        self.reponses = [ok_json()]
        self.client(cle="SECRET123").consulter("ip-src", "8.8.4.4")
        with open(self.cache, encoding="utf-8") as f:
            self.assertNotIn("SECRET123", f.read())

    def test_valeur_echappee(self):
        self.reponses = [http(404)]
        self.client().consulter("domain", "a/b?c")
        self.assertTrue(self.appels[0].full_url.endswith("/domains/a%2Fb%3Fc"))

    def test_timeout(self):
        self.reponses = [TimeoutError()]
        self.assertEqual(self.client().consulter("ip-src", "8.8.4.4").statut, "indisponible")

    def test_urlerror(self):
        self.reponses = [urllib.error.URLError("dns")]
        self.assertEqual(self.client().consulter("ip-src", "8.8.4.4").statut, "indisponible")

    def test_cle_absente(self):
        r = self.client(cle=None).consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels)), ("cle_absente", 0))

    def test_rfc5737_non_soumise(self):
        r = self.client().consulter("ip-src", "203.0.113.200")
        self.assertEqual((r.statut, len(self.appels)), ("non_soumis", 0))
        self.assertIn("RFC 5737", r.message)

    def test_privee_non_routable(self):
        r = self.client().consulter("ip-src", "10.1.2.3")
        self.assertEqual((r.statut, len(self.appels)), ("non_soumis", 0))
        self.assertIn("non routable", r.message)

    def test_type_non_applicable(self):
        r = self.client().consulter("target-user", "bob")
        self.assertEqual((r.statut, len(self.appels)), ("non_applicable", 0))

    def test_cache(self):
        self.reponses = [ok_json()]
        c = self.client()
        c.consulter("ip-src", "8.8.4.4")
        r = c.consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels)), ("ok", 1))
        c2 = self.client()
        r = c2.consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels), r.donnees["malicious"]), ("ok", 1, 3))
        self.assertFalse(os.path.exists(self.cache + ".tmp"))

    def test_sans_cache_disque(self):
        # chemin_cache=None : rien n'est écrit, chaque exécution réinterroge VT ;
        # une même valeur n'est demandée qu'une fois au cours d'une exécution.
        self.reponses = [ok_json(), ok_json()]
        c = ClientVT("K", None, urlopen=self.urlopen, horloge=lambda: self.t[0],
                     dormir=self.sommeils.append)
        c.consulter("ip-src", "8.8.4.4")
        c.consulter("ip-src", "8.8.4.4")
        self.assertEqual(len(self.appels), 1)
        c2 = ClientVT("K", None, urlopen=self.urlopen, horloge=lambda: self.t[0],
                      dormir=self.sommeils.append)
        r = c2.consulter("ip-src", "8.8.4.4")
        self.assertEqual((r.statut, len(self.appels)), ("ok", 2))
        self.assertEqual(os.listdir(self.dossier), [])

    def test_cache_expire(self):
        self.reponses = [ok_json(), ok_json()]
        c = self.client()
        c.consulter("ip-src", "8.8.4.4")
        self.t[0] += 25 * 3600
        c.consulter("ip-src", "8.8.4.4")
        self.assertEqual(len(self.appels), 2)

    def test_indisponible_non_cache(self):
        self.reponses = [TimeoutError(), ok_json()]
        c = self.client()
        c.consulter("ip-src", "8.8.4.4")
        self.assertEqual(c.consulter("ip-src", "8.8.4.4").statut, "ok")

    def test_cache_corrompu(self):
        with open(self.cache, "w") as f:
            f.write("{pas du json")
        self.reponses = [ok_json()]
        self.assertEqual(self.client().consulter("ip-src", "8.8.4.4").statut, "ok")

    def test_intervalle(self):
        self.reponses = [ok_json(), ok_json()]
        c = self.client()
        c.consulter("ip-src", "8.8.4.4")
        self.assertEqual(self.sommeils, [])
        c.consulter("ip-src", "8.8.8.8")
        self.assertEqual(self.sommeils, [15])

    def test_enrichir_iocs(self):
        self.reponses = [ok_json(), http(404)]
        iocs = [
            IOC("8.8.4.4", "ip-src", "Network activity", True, "c"),
            IOC("bob", "target-user", "Payload delivery", False, "c"),
            IOC("203.0.113.9", "ip-src", "Network activity", True, "c"),
            IOC("evil.example.net", "domain", "Network activity", True, "c"),
        ]
        cpt = enrichir_iocs(iocs, self.client())
        self.assertEqual(cpt, {"ok": 1, "non_applicable": 1, "non_soumis": 1, "inconnu": 1})
        self.assertEqual(iocs[0].statut_enrichissement, "ok")
        self.assertEqual(iocs[0].enrichissement["malicious"], 3)
        self.assertEqual(iocs[1].statut_enrichissement, "non_applicable")
        self.assertIn("RFC 5737", iocs[2].enrichissement["message"])
        self.assertEqual(iocs[3].statut_enrichissement, "inconnu")


if __name__ == "__main__":
    unittest.main()


def ok_riche(**extra):
    res = {f"Moteur{c}": {"category": "harmless", "result": "clean"} for c in "XYZ"}
    res["ZetaAV"] = {"category": "malicious", "result": "malware"}
    res["CyRadar"] = {"category": "malicious", "result": "malware"}
    res["Susp"] = {"category": "suspicious", "result": "phishing"}
    return ok_json(country="US", asn=14618, as_owner="Amazon.com, Inc.",
                   network="50.16.0.0/14", last_analysis_results=res,
                   total_votes={"harmless": 0, "malicious": 2}, reputation=-3,
                   tags=["scanner"], **extra)


class TestDetailsVT(Base):
    def test_extraire_garde_details(self):
        self.reponses = [ok_riche()]
        d = self.client().consulter("ip-src", "50.16.16.211").donnees
        self.assertEqual((d["asn"], d["network"], d["tags"]), (14618, "50.16.0.0/14", ["scanner"]))
        self.assertEqual(d["total_votes"], {"harmless": 0, "malicious": 2})
        self.assertEqual([m["moteur"] for m in d["moteurs"]], ["CyRadar", "Susp", "ZetaAV"])
        self.assertEqual(d["nb_moteurs_signales"], 3)
        self.assertEqual(d["lien"], "https://www.virustotal.com/gui/ip-address/50.16.16.211")

    def test_moteurs_plafonnes(self):
        res = {f"M{n:02d}": {"category": "malicious", "result": "x"} for n in range(20)}
        self.reponses = [ok_json(last_analysis_results=res)]
        d = self.client().consulter("domain", "a.fr").donnees
        self.assertEqual((len(d["moteurs"]), d["nb_moteurs_signales"]), (15, 20))

    def test_champs_absents_non_conserves(self):
        self.reponses = [ok_json()]
        d = self.client().consulter("md5", "a" * 32).donnees
        for cle in ("asn", "moteurs", "tags", "total_votes"):
            self.assertNotIn(cle, d)
        self.assertTrue(d["lien"].endswith("/file/" + "a" * 32))


def ioc_enrichi(corps, valeur="50.16.16.211"):
    i = IOC(type_misp="ip-src", valeur=valeur, categorie_misp="Network activity",
            commentaire="c", to_ids=True)
    c = ClientVT("K", None, urlopen=lambda req, timeout=None: corps)
    enrichir_iocs([i], c)
    return i


class TestAffichageDetails(unittest.TestCase):
    def test_texte_etape5(self):
        from investigation import expliquer_etape5
        i = ioc_enrichi(ok_riche())
        t = expliquer_etape5([i], {"ok": 1})
        for attendu in ("États-Unis (US)", "AS14618", "CyRadar (malveillant : malware)",
                        "Susp (suspect : phishing)", "Fiche VirusTotal",
                        "14/11/2023 22:13 UTC", "50.16.0.0/14", "Amazon.com, Inc.",
                        "Réputation communautaire : -3", "2 malveillants", "scanner",
                        "3 malveillants, 1 suspect, 50 sans danger, 10 non détectés"):
            self.assertIn(attendu, t)
        self.assertEqual(t.count("la réputation est le score"), 1)

    def test_donnees_absentes_pas_de_ligne_vide(self):
        from investigation import _lignes_detail_vt
        i = ioc_enrichi(Reponse(json.dumps({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "harmless": 5}}}}).encode()))
        lignes = _lignes_detail_vt(i)
        self.assertTrue(all(l.strip() for l in lignes))
        self.assertFalse(any(l.startswith(("Pays", "Moteurs", "Réputation")) for l in lignes))

    def test_pays_inconnu_repli_code(self):
        from investigation import _pays
        self.assertEqual(_pays("ZZ"), "ZZ")

    def test_commentaire_misp(self):
        from iocs import exporter_misp_csv
        i = ioc_enrichi(ok_riche())
        chemin = os.path.join(tempfile.mkdtemp(), "m.csv")
        exporter_misp_csv([i], chemin)
        with open(chemin, encoding="utf-8") as f:
            self.assertIn("VT : 3/64 malveillant, US, Amazon.com, Inc.", f.read())
