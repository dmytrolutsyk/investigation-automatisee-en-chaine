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
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


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
