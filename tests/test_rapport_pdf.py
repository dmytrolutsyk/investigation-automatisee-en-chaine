import builtins
import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from investigation import construire_donnees_rapport, investiguer, main
from iocs import IOC
from tests.jeu_synthetique import IP_SPRAY_A, IP_SPRAY_B, construire_jeu, ecrire_jeu

REPORTLAB = importlib.util.find_spec("reportlab") is not None
GENERE_LE = datetime(2026, 5, 20, 14, 30, tzinfo=timezone.utc)


class _Base(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dossier, True)

    def jeu(self, evenements=None):
        chemin = ecrire_jeu(evenements)
        self.addCleanup(os.remove, chemin)
        return chemin


class TestDonneesRapport(_Base):
    def test_cles_et_formes(self):
        d = construire_donnees_rapport(investiguer(self.jeu()), GENERE_LE)
        for cle in ("titre", "periode", "gravite", "synthese", "actions_prioritaires",
                    "etapes", "chronologie", "plan", "iocs", "genere_le"):
            self.assertIn(cle, d)
        self.assertEqual(d["gravite"], "CRITIQUE")
        self.assertEqual(len(d["synthese"]), 3)
        self.assertTrue(all(isinstance(p, str) and p.endswith(".") for p in d["synthese"]))
        self.assertEqual(len(d["etapes"]), 5)
        self.assertTrue(all(set(e) == {"titre", "texte"} for e in d["etapes"]))
        self.assertTrue(all(len(l) == 3 for l in d["plan"]))
        self.assertTrue(all(len(l) == 4 for l in d["chronologie"]))
        self.assertTrue(all(len(l) == 3 for l in d["iocs"]))
        self.assertIn("20/05/2026", d["genere_le"])
        self.assertIn("UTC", d["periode"])

    def test_contenu_synthese_et_actions(self):
        inv = investiguer(self.jeu())
        d = construire_donnees_rapport(inv, GENERE_LE)
        synthese = " ".join(d["synthese"])
        for attendu in (IP_SPRAY_A, "SRV-FILE02", "u.trois", "adm_tmp", "critique"):
            self.assertIn(attendu, synthese)
        attendues = [a.action for a in inv.actions if a.priorite == "IMMÉDIAT"]
        self.assertEqual(d["actions_prioritaires"], attendues)
        self.assertTrue(any("Isoler SRV-FILE02" in a for a in d["actions_prioritaires"]))

    def test_etapes_reprennent_les_explications(self):
        d = construire_donnees_rapport(investiguer(self.jeu()), GENERE_LE)
        self.assertTrue(d["etapes"][0]["texte"].startswith("Recherche :"))
        self.assertNotIn("===", d["etapes"][0]["texte"])
        self.assertIn("DÉTECTION", d["etapes"][0]["titre"].upper())
        self.assertIn("[!]", d["etapes"][2]["texte"])

    def test_chronologie_et_iocs(self):
        d = construire_donnees_rapport(investiguer(self.jeu()), GENERE_LE)
        heures = [l[0] for l in d["chronologie"]]
        self.assertEqual(heures, sorted(heures))
        self.assertIn(["09:12", "SRV-FILE02", "u.trois"], [l[:3] for l in d["chronologie"]])
        par_valeur = {l[0]: l for l in d["iocs"]}
        self.assertEqual(par_valeur[IP_SPRAY_A][1], "IP d'attaque")
        self.assertEqual(par_valeur["u.trois"][1], "compte compromis")
        self.assertEqual(par_valeur["adm_tmp"][1], "compte créé")
        self.assertEqual(par_valeur["\\OneDriveSyncHelper"][1], "tâche planifiée")
        self.assertEqual(par_valeur[IP_SPRAY_A][2], "non vérifié")

    def test_statut_vt(self):
        inv = investiguer(self.jeu())
        inv.iocs = [IOC("8.8.8.8", "ip-src", "Network activity", True, "c",
                        "ok", {"malicious": 3, "harmless": 60}, "ip_attaque")]
        inv.comptage_vt = {"ok": 1}
        d = construire_donnees_rapport(inv, GENERE_LE)
        self.assertIn("3 moteurs sur 63", d["iocs"][0][2])

    def test_jeu_sans_suspect(self):
        legitimes = [e for e in construire_jeu() if e["account"] == "p.alpha"]
        d = construire_donnees_rapport(investiguer(self.jeu(legitimes)), GENERE_LE)
        self.assertEqual(len(d["synthese"]), 3)
        self.assertEqual(d["gravite"], "FAIBLE")
        self.assertIn("aucune", d["synthese"][0].lower())
        self.assertEqual(d["actions_prioritaires"], [])
        self.assertEqual(d["iocs"], [])

    def test_attaque_non_aboutie(self):
        evts = [e for e in construire_jeu() if e.get("src_ip") == IP_SPRAY_B]
        d = construire_donnees_rapport(investiguer(self.jeu(evts)), GENERE_LE)
        self.assertEqual(d["gravite"], "MODÉRÉE")
        self.assertIn("aucune connexion", d["synthese"][1].lower())

    def test_jeu_vide(self):
        d = construire_donnees_rapport(investiguer(self.jeu([])), GENERE_LE)
        self.assertEqual(len(d["synthese"]), 3)
        self.assertEqual(d["chronologie"], [])


@unittest.skipUnless(REPORTLAB, "reportlab absent")
class TestPDF(_Base):
    def generer(self, evenements=None):
        from rapport_pdf import generer_pdf
        chemin = os.path.join(self.dossier, "r.pdf")
        generer_pdf(chemin, construire_donnees_rapport(investiguer(self.jeu(evenements)),
                                                       GENERE_LE))
        return chemin

    def test_pdf_genere(self):
        with open(self.generer(), "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")

    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext absent")
    def test_contenu(self):
        texte = subprocess.run(["pdftotext", self.generer(), "-"],
                               capture_output=True, text=True).stdout
        for attendu in (IP_SPRAY_A, "u.trois", "SRV-FILE02", "adm_tmp", "CRITIQUE",
                        "OneDriveSyncHelper", "ForCERT", "Admins du domaine",
                        "Document généré automatiquement le 20/05/2026"):
            self.assertIn(attendu, texte)
        self.assertNotIn("&lt;", texte)
        self.assertNotIn("&amp;", texte)

    def test_texte_a_echapper(self):
        evts = construire_jeu()
        for e in evts:
            if e["event_id"] == 4698:
                e["details"]["task_name"] = "\\A<b>&C"
        chemin = self.generer(evts)
        if shutil.which("pdftotext"):
            texte = subprocess.run(["pdftotext", chemin, "-"],
                                   capture_output=True, text=True).stdout
            self.assertIn("\\A<b>&C", texte)

    def test_jeu_vide(self):
        with open(self.generer([]), "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")


class TestMainPDF(_Base):
    def lancer(self, argv):
        ancien = os.getcwd()
        os.chdir(self.dossier)
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(argv)
        finally:
            os.chdir(ancien)
        return code, out.getvalue(), err.getvalue()

    @unittest.skipUnless(REPORTLAB, "reportlab absent")
    def test_main_produit_pdf(self):
        code, out, _ = self.lancer([self.jeu()])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.dossier, "rapport_incident.pdf")))
        self.assertIn("rapport_incident.pdf", out.split("Fichiers produits")[1])

    def test_main_sans_reportlab(self):
        vrai_import = builtins.__import__

        def faux_import(nom, *args, **kwargs):
            if nom == "rapport_pdf" or nom.startswith("reportlab"):
                raise ImportError(nom)
            return vrai_import(nom, *args, **kwargs)

        with mock.patch("builtins.__import__", faux_import):
            code, out, _ = self.lancer([self.jeu()])
        self.assertEqual(code, 0)
        self.assertIn("PDF non généré : reportlab absent", out)
        self.assertFalse(os.path.exists(os.path.join(self.dossier, "rapport_incident.pdf")))

    @unittest.skipUnless(REPORTLAB, "reportlab absent")
    def test_main_erreur_ecriture_pdf(self):
        with mock.patch("rapport_pdf.generer_pdf", side_effect=OSError("disque plein")):
            code, _, err = self.lancer([self.jeu()])
        self.assertEqual(code, 1)
        self.assertIn("disque plein", err)


if __name__ == "__main__":
    unittest.main()
