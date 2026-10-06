import json
import os
import tempfile
import unittest
from datetime import timezone

from investigation import ErreurChargement, charger_logs
from tests.jeu_synthetique import chemin_jeu_synthetique


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


if __name__ == "__main__":
    unittest.main()
