import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from investigation import (ErreurChargement, Evenement, charger_logs, est_interne,
                           etape1_detection, etape2_pivot, expliquer_etape1,
                           expliquer_etape2, formater_heure)
from tests.jeu_synthetique import (IP_BRUTE, IP_FP, IP_SPRAY_A, IP_SPRAY_B,
                                   chemin_jeu_synthetique, construire_jeu, ecrire_jeu)


def ecrire_tmp(objets):
    """Écrit objets en JSON dans un fichier temporaire supprimé en fin de test."""
    with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(objets, f)
    return f.name


class TestChargement(unittest.TestCase):
    def _tmp(self, objets):
        chemin = ecrire_tmp(objets)
        self.addCleanup(os.remove, chemin)
        return chemin

    def test_tri_et_formats_horodatage(self):
        chemin = self._tmp([
            {"timestamp": "2026-05-20T10:00:12.5Z", "event_id": 4624},
            {"timestamp": "2026-05-20T09:00:00+00:00", "event_id": 4625},
            {"timestamp": "2026-05-20T08:00:00Z", "event_id": 4688},
        ])
        evts = charger_logs(chemin)
        self.assertEqual([e.timestamp for e in evts],
                         sorted(e.timestamp for e in evts))
        self.assertEqual([e.event_id for e in evts], [4688, 4625, 4624])
        self.assertEqual(evts[0].timestamp.tzinfo, timezone.utc)

    def test_champs_manquants(self):
        chemin = self._tmp(
            [{"timestamp": "2026-05-20T08:00:00Z", "event_id": 4625, "details": None}])
        e = charger_logs(chemin)[0]
        self.assertEqual((e.host, e.account, e.src_ip, e.details), ("", "", None, {}))
        self.assertEqual((e.logon_type, e.result), (None, ""))

    def test_timestamp_invalide_ignore(self):
        chemin = self._tmp([{"event_id": 4625},
                            {"timestamp": "n'importe quoi", "event_id": 4625},
                            {"timestamp": "2026-05-20T08:00:00Z", "event_id": 4624}])
        self.assertEqual(len(charger_logs(chemin)), 1)

    def test_fichier_absent(self):
        with self.assertRaises(ErreurChargement):
            charger_logs("inexistant.json")

    def test_json_invalide(self):
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("ceci n'est pas du JSON")
        self.addCleanup(os.remove, f.name)
        with self.assertRaises(ErreurChargement):
            charger_logs(f.name)

    def test_racine_non_liste(self):
        with self.assertRaises(ErreurChargement):
            charger_logs(self._tmp({"timestamp": "2026-05-20T08:00:00Z"}))

    def test_jeu_synthetique_charge(self):
        chemin = chemin_jeu_synthetique()
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        self.assertEqual(len(evts), 2 + 12 + 12 + 7 + 15 + 11)
        self.assertEqual([e.timestamp for e in evts],
                         sorted(e.timestamp for e in evts))


class TestEtape1(unittest.TestCase):
    def _evts(self):
        chemin = chemin_jeu_synthetique()
        self.addCleanup(os.remove, chemin)
        return charger_logs(chemin)

    def setUp(self):
        self.det = etape1_detection(self._evts())

    def test_suspectes_et_categories(self):
        self.assertEqual(
            [(p.ip, p.categorie, p.nb_echecs, len(p.comptes)) for p in self.det.suspectes],
            [(IP_SPRAY_A, "spraying", 12, 6), (IP_SPRAY_B, "spraying", 15, 8),
             (IP_BRUTE, "force_brute", 11, 1)])

    def test_faux_positif_ecarte(self):
        self.assertEqual([(p.ip, p.categorie) for p in self.det.ecartees],
                         [(IP_FP, "faux_positif_probable")])

    def test_fenetre(self):
        a = self.det.suspectes[0]
        self.assertEqual((a.debut.strftime("%H:%M:%S"), a.fin.strftime("%H:%M:%S")),
                         ("09:00:00", "09:07:20"))
        self.assertEqual(a.hosts, ["SRV-FILE02"])

    def test_totaux(self):
        self.assertEqual(self.det.nb_echecs_total, 12 + 12 + 15 + 11)
        self.assertEqual(self.det.nb_ip_analysees, 4)

    def test_incoherence_result_comptee(self):
        self.assertEqual(self.det.nb_incoherences_result, 12 + 12 + 15 + 11)

    def test_est_interne(self):
        self.assertTrue(est_interne("10.8.0.50"))
        self.assertFalse(est_interne("203.0.113.200"))
        self.assertFalse(est_interne("pas-une-ip"))

    def test_seuils_parametrables(self):
        det = etape1_detection(self._evts(), seuil_echecs=13)
        self.assertEqual(det.suspectes[0].ip, IP_SPRAY_B)

    def test_formater_heure(self):
        dt = self.det.suspectes[0].debut
        self.assertEqual(formater_heure(dt, False), "09:00")
        self.assertEqual(formater_heure(dt, True), "20/05 09:00")

    def test_explication(self):
        t = expliquer_etape1(self.det, multi_jours=False)
        for attendu in ("=== ÉTAPE 1", "Recherche :", "Résultat :", "->", IP_SPRAY_A,
                        "12 échecs", "6 comptes", "09:00", "password spraying",
                        "force brute", IP_FP, "svc_web", "compte de service"):
            self.assertIn(attendu, t)

    def test_seuils_dans_explication(self):
        det = etape1_detection(self._evts(), seuil_echecs=13, seuil_comptes=7)
        t = expliquer_etape1(det, multi_jours=False)
        self.assertIn("à partir de 13 échecs", t)
        self.assertIn("au moins 7 comptes", t)
        self.assertNotIn("à partir de 10 échecs", t)

    def test_singulier_force_brute(self):
        t = expliquer_etape1(self.det, multi_jours=False)
        ligne = [l for l in t.splitlines() if IP_BRUTE in l][0]
        self.assertIn("1 compte,", ligne)
        self.assertNotIn("1 comptes", t)
        self.assertIn("machine visée : SRV-VPN01", ligne)

    def test_multi_jours_dans_explication(self):
        t = expliquer_etape1(self.det, multi_jours=True)
        self.assertIn("20/05 09:00", t)

    @staticmethod
    def _echecs(ip, comptes, n, event_id=4625):
        base = datetime(2026, 5, 20, 8, 0, tzinfo=timezone.utc)
        return [Evenement(base + timedelta(seconds=i), event_id, "H1",
                          comptes[i % len(comptes)], ip, 3, "", {})
                for i in range(n)]

    def test_interne_plusieurs_comptes_sous_seuil_ecartee(self):
        det = etape1_detection(self._echecs("10.1.1.1", ["a", "b", "c"], 12))
        self.assertEqual(det.suspectes, [])
        self.assertEqual([(p.ip, p.categorie) for p in det.ecartees],
                         [("10.1.1.1", "sous_seuil")])

    def test_sous_seuil_echecs_non_ecartee(self):
        det = etape1_detection(self._echecs("198.51.100.9", ["a", "b"], 9))
        self.assertEqual((det.suspectes, det.ecartees), ([], []))
        self.assertEqual(det.nb_ip_analysees, 1)

    def test_src_ip_absente_ignoree(self):
        evts = self._echecs(None, ["a"], 20) + self._echecs("", ["a"], 20)
        det = etape1_detection(evts)
        self.assertEqual((det.nb_echecs_total, det.nb_ip_analysees), (0, 0))
        self.assertEqual((det.suspectes, det.ecartees), ([], []))

    def test_4624_non_compte(self):
        evts = self._echecs("198.51.100.9", ["a"], 20, event_id=4624)
        det = etape1_detection(evts)
        self.assertEqual((det.nb_echecs_total, det.suspectes), (0, []))

    def test_aucune_ip_suspecte(self):
        t = expliquer_etape1(etape1_detection([]), multi_jours=False)
        self.assertIn("Aucune IP", t)


class TestEtape2(unittest.TestCase):
    def _pivot(self, supplementaires=()):
        chemin = ecrire_jeu(construire_jeu() + list(supplementaires))
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        return etape2_pivot(evts, etape1_detection(evts))

    @staticmethod
    def _succes(ts, host, compte, ip, logon_type=3):
        return {"timestamp": ts, "event_id": 4624, "host": host, "account": compte,
                "src_ip": ip, "logon_type": logon_type, "result": "success",
                "details": {}}

    def test_compromission_synthetique(self):
        piv = self._pivot()
        self.assertEqual(
            [(x.ip, x.compte, x.host, x.t0.strftime("%H:%M"), x.logon_type)
             for x in piv.compromissions],
            [(IP_SPRAY_A, "u.trois", "SRV-FILE02", "09:12", 3)])
        self.assertEqual([p.ip for p in piv.non_abouties], [IP_SPRAY_B, IP_BRUTE])

    def test_succes_avant_premier_echec_ignore(self):
        # Connexion légitime à 09:59, avant le premier échec de l'IP (10:00)
        piv = self._pivot([self._succes("2026-05-20T09:59:00Z", "WKS-110", "v.a",
                                        IP_SPRAY_B)])
        self.assertEqual([x.ip for x in piv.compromissions], [IP_SPRAY_A])
        self.assertIn(IP_SPRAY_B, [p.ip for p in piv.non_abouties])

    def test_plusieurs_couples(self):
        piv = self._pivot([
            self._succes("2026-05-20T09:13:00Z", "SRV-FILE03", "u.un", IP_SPRAY_A),
            # même couple que l'original, plus tard : une seule compromission
            self._succes("2026-05-20T09:40:00Z", "SRV-FILE02", "u.trois", IP_SPRAY_A)])
        self.assertEqual(
            [(x.compte, x.host, x.t0.strftime("%H:%M")) for x in piv.compromissions],
            [("u.trois", "SRV-FILE02", "09:12"), ("u.un", "SRV-FILE03", "09:13")])
        self.assertEqual([p.ip for p in piv.non_abouties], [IP_SPRAY_B, IP_BRUTE])

    def test_explication(self):
        t = expliquer_etape2(self._pivot(), False)
        for attendu in ("=== ÉTAPE 2", "u.trois", "SRV-FILE02", "09:12", "a abouti",
                        "accès réseau", IP_SPRAY_B, "n'a pas abouti"):
            self.assertIn(attendu, t)

    def test_explication_sans_ip_suspecte(self):
        evts = []
        piv = etape2_pivot(evts, etape1_detection(evts))
        self.assertIn("rien à pivoter", expliquer_etape2(piv, False))


if __name__ == "__main__":
    unittest.main()
