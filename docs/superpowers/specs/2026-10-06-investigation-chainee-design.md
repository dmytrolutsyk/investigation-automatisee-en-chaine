# Spec — Investigation automatisée en chaîne (exercice ForCERT)

Date : 2026-10-06
Source des exigences : `exercice.md`

## 1. Objectif

Script Python 3 qui, à partir d'un export JSON de journaux Windows, enchaîne
quatre étapes (détection → pivot → chronologie → remédiation) sans aucune
valeur saisie à la main, et explique chaque étape en français clair
(recherche / résultat / transition). Le script doit fonctionner tel quel sur
un second jeu de données inconnu de même format.

Périmètre retenu : socle + bonus « export PDF à la charte Formind » +
extraction des IOC, enrichissement VirusTotal (seule source) et exports
MISP (CSV) / STIX 2.1.
Inclus aussi, car nécessaires à la robustesse : gestion multi-IP /
multi-machines et écartement des faux positifs « compte de service ».
Hors périmètre : seuil adaptatif, règles Splunk, Word, autres sources
d'enrichissement (AbuseIPDB, OTX, Shodan…), mapping MITRE ATT&CK.

## 2. Contraintes

- Bibliothèques autorisées : stdlib (json, datetime, collections, urllib,
  ipaddress, base64, re, uuid…), pandas, reportlab (installés via apt :
  `python3-pandas` 2.3.3, `python3-reportlab` 4.4.10).
- Choix : le cœur (`investigation.py`, `iocs.py`, `enrichissement_vt.py`)
  reste en stdlib pour tourner sur n'importe quelle machine du correcteur ;
  pandas n'est pas utilisé (l'agrégation de l'étape 1 tient en quelques
  lignes avec `collections`).
- `rapport_pdf.py` : dépend de `reportlab`, importé de façon optionnelle.
  Absent → le script produit la sortie texte et signale que le PDF est sauté
  (pas d'échec).
- Tous les paramètres (chemins, seuils, listes de référence) en tête de
  `investigation.py`. Chemin des logs surchargeable par `argv[1]`.
- Aucune IP, compte, machine ou horaire du jeu fourni dans le code.

## 3. Architecture

```
charger_logs(chemin) -> list[Evenement]
etape1_detection(evts) -> ResultatDetection {suspectes, ecartees}
etape2_pivot(evts, suspectes) -> list[Compromission]
etape3_chronologie(evts, compromissions) -> list[Chronologie]
etape4_plan(detection, compromissions, chronologies) -> list[Action]
etape5_iocs(detection, compromissions, chronologies, enrichir) -> list[IOC]
expliquer_etapeN(resultat) -> str            # texte en 3 temps
main() -> console + sortie_rapport.txt + iocs_misp.csv + iocs_stix.json
          (+ rapport_incident.pdf)
```

Modules :
- `investigation.py` : paramètres, chargement, étapes 1–5, explications, CLI.
- `iocs.py` : extraction des IOC, exports MISP CSV et STIX 2.1.
- `enrichissement_vt.py` : client VirusTotal (cache, rate limit, retries).
- `rapport_pdf.py` : rendu PDF reportlab.

CLI : `python3 investigation.py [chemin_logs.json] [--enrichir]`.

Les étapes sont des fonctions pures renvoyant des structures (dataclasses).
Le texte et le PDF sont produits à partir des mêmes structures.
Timestamps parsés en `datetime` UTC (suffixe `Z` géré).

## 4. Logique par étape

### Étape 1 — Détection
- Filtre : `event_id == 4625` (le champ `result` n'est pas utilisé ;
  si des 4625 portent `result == "success"`, une note d'incohérence est émise).
- Événements avec `src_ip` null ignorés.
- Agrégat par IP : nb d'échecs, comptes distincts, hosts visés, premier et
  dernier horodatage.
- Classification (paramètres `SEUIL_ECHECS = 10`, `SEUIL_COMPTES = 5`) :
  - `spraying` : échecs ≥ SEUIL_ECHECS et comptes ≥ SEUIL_COMPTES → suspecte ;
  - `force_brute` : échecs ≥ SEUIL_ECHECS, comptes < SEUIL_COMPTES, IP non
    interne → suspecte ;
  - `faux_positif_probable` : échecs ≥ SEUIL_ECHECS, un seul compte, IP
    interne → écartée, citée avec motif ;
  - IP interne, plusieurs comptes mais < SEUIL_COMPTES → écartée « sous le
    seuil » ;
  - sinon : sous le seuil, non retenue.
- « Interne » = appartient à `RESEAUX_INTERNES` (paramètre, défaut
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). On n'utilise pas
  `ipaddress.is_private`, qui classe aussi les plages de documentation
  RFC 5737 (ex. 203.0.113.0/24) comme privées.
- IP invalide (non parsable) : traitée comme non interne.

### Étape 2 — Pivot
- Pour chaque IP suspecte : 4624 dont `src_ip` = IP et timestamp ≥ premier
  échec de cette IP.
- Une compromission par couple (compte, host) distinct, `t0` = première
  connexion réussie de ce couple ; on conserve `logon_type`.
- IP suspecte sans succès → « tentative non aboutie » (transmise à l'étape 4).

### Étape 3 — Chronologie
Pour chaque compromission :
- Comptes suivis = {compte compromis} ∪ comptes créés (4720 `new_account`)
  dans le périmètre, ajoutés au fil de l'eau (ordre chronologique).
- Événements retenus : timestamp ≥ t0, hors 4625, et
  (`host` == host compromis ou `account` ∈ comptes suivis ou, pour 4732,
  `details.member` ∈ comptes suivis). La connexion t0 elle-même est incluse.
- Qualification :
  - 4688 suspect si (parent ∈ `PARENTS_BUREAUTIQUES` et process ∈
    `INTERPRETEURS`) ou ligne de commande contenant un marqueur de
    `MARQUEURS_CMD_SUSPECTS` (`-enc`, `-encodedcommand`, `-nop`, `hidden`,
    `downloadstring`, `iex`) ; sinon bénin. Paramètre `-enc` → décodage
    base64 UTF-16LE best-effort (échec → « non décodable »).
  - 4698 persistance (task_name) ; 4720 création de compte (new_account) ;
    4732 ajout à groupe, critique si group ∈ `GROUPES_PRIVILEGIES`
    (FR + EN : Administrateurs, Administrators, Admins du domaine,
    Domain Admins, Enterprise Admins, Remote Desktop Users, …) ;
    1102 effacement de journal ; 4624 sur un autre host → mouvement latéral.
- Les événements bénins restent dans la chronologie, marqués comme tels.

### Étape 4 — Plan d'action
Règles fait → action, chaque action nomme l'objet et porte une priorité
(`IMMEDIAT`, `COURT_TERME`, `SUIVI`) :

| Fait | Action | Priorité |
|---|---|---|
| IP suspecte (aboutie ou non) | bloquer l'IP au pare-feu / proxy | immédiat |
| Compromission (compte, host) | isoler le host | immédiat |
| idem | réinitialiser le mot de passe du compte, révoquer ses sessions | immédiat |
| 4720 compte X | désactiver X | immédiat |
| 4732 X dans groupe G | retirer X de G | immédiat |
| 4698 tâche T | supprimer T sur le host | court terme |
| 4688 suspect | collecte forensique du host, analyser la commande (décodée) | court terme |
| 1102 | traçabilité locale perdue → s'appuyer sur le SIEM / sauvegardes | court terme |
| mouvement latéral vers H | isoler H, étendre l'investigation | immédiat |
| tentative non aboutie | surveiller / forcer MFA sur les comptes visés | suivi |
| faux positif écarté | vérifier le mot de passe du compte de service | suivi |
| Comptes visés par spraying | revue des mots de passe faibles, MFA | suivi |

Dédoublonnage des actions identiques.

### Étape 5 — IOC, enrichissement et exports

**Extraction** (depuis les résultats des étapes 1–3, jamais en dur) :

| IOC | Source | type MISP | category MISP | to_ids |
|---|---|---|---|---|
| IP suspecte | étape 1 | ip-src | Network activity | 1 |
| Hash md5/sha1/sha256 | regex sur details + cmd décodées | md5/sha1/sha256 | Payload delivery | 1 |
| URL | regex | url | Network activity | 1 |
| Domaine | regex | domain | Network activity | 1 |
| IPv4 dans une commande | regex | ip-dst | Network activity | 1 |
| Compte créé (4720) | étape 3 | text | Persistence mechanism | 0 |
| Tâche planifiée (4698) | étape 3 | text | Persistence mechanism | 0 |
| Ligne de commande suspecte | étape 3 | text | Payload installation | 0 |
| Compte compromis | étape 2 | target-user | Targeting data | 0 |
| Machine touchée | étapes 2–3 | target-machine | Targeting data | 0 |

Les couples type/category sont validés contre le `describeTypes.json` de
MISP lors de l'implémentation (ajustement si un couple est refusé).
Dédoublonnage par (type, valeur).

**Enrichissement VirusTotal** (`enrichissement_vt.py`, `urllib`), uniquement
avec `--enrichir` :
- Consultation seule (jamais d'upload) : `/api/v3/ip_addresses/{ip}`,
  `/domains/{d}`, `/urls/{id base64url}`, `/files/{hash}`. Seuls IP,
  domaines, URL et hashes sont soumis.
- IP non `is_global` (privée, réservée, documentation RFC 5737) → non
  soumise, statut explicite (« plage de documentation RFC 5737, non
  soumise »).
- Clé : variable d'environnement `VT_API_KEY` ; absente → étape sautée
  avec explication.
- Cache disque `cache_vt.json`, clé `type:valeur`, TTL 24 h
  (paramètre).
- Rate limit : ≥ 15 s entre deux requêtes réelles (paramètre ; les hits
  cache ne comptent pas).
- 429 → retry backoff exponentiel, 3 essais max ; 404 → « inconnu de
  VirusTotal » ; 401/403 → clé invalide, arrêt propre de l'enrichissement ;
  timeout 10 s / erreur réseau → « source indisponible », on continue.
- Données gardées : `malicious`, `suspicious`, `harmless`, `undetected`
  (last_analysis_stats), `reputation`, `country`, `as_owner`,
  `last_analysis_date`.
- Les verdicts n'influencent pas le plan (déterminisme) ; ils apparaissent
  dans l'annexe IOC (texte + PDF) et dans les commentaires des exports.

**Exports** :
- `iocs_misp.csv` : `value,type,category,to_ids,comment`, une ligne par IOC ;
  un fichier = un événement MISP (incident). `comment` = fait observé
  (+ verdict VT si disponible).
- `iocs_stix.json` : bundle STIX 2.1 écrit en JSON pur : `identity`
  (auteur « ForCERT - investigation automatisée »), `indicator`
  (pattern STIX, `pattern_type: stix`, `valid_from` = premier horodatage
  observé) pour IP/hash/URL/domaine, `user-account` pour les comptes,
  `report` (`published` = date de génération) référençant tous les objets.
  IDs déterministes `uuid5` (namespace fixe + type + valeur) pour éviter
  les doublons à la réimportation dans OpenCTI.
- Rappel de prudence dans le rapport : aucun fichier ni échantillon
  client n'est envoyé à une plateforme publique.

## 5. Explications automatiques

Chaque étape produit un bloc :
```
=== ÉTAPE N : TITRE ===
Recherche : <ce que je cherche, paramètres utilisés>
Résultat : <valeurs réelles>
-> <ce que je fais ensuite>
```
Cas vides gérés explicitement (aucune IP suspecte → étapes suivantes
indiquent qu'il n'y a rien à pivoter, plan minimal). Horaires affichés
HH:MM (UTC précisé dans l'en-tête), date incluse si la fenêtre couvre
plusieurs jours.

## 6. Sorties

- Console + `sortie_rapport.txt` (contenu identique), étapes 1–5.
- `iocs_misp.csv`, `iocs_stix.json` (toujours produits, même sans
  enrichissement).
- `rapport_incident.pdf` si reportlab disponible, charte Formind :
  marine `#1B2A4A`, turquoise `#1FA3A8`, titres en pastilles arrondies,
  police Helvetica. Contenu : synthèse non technique (gravité, 3 phrases,
  actions prioritaires), 4 étapes, tableau chronologie, tableau
  fait → action → priorité, annexe IOC (avec verdict VT ou statut),
  pied de page (date de génération, « généré
  automatiquement »).
- Chemins de sortie paramétrés en tête de script, relatifs au dossier
  courant.

## 7. Gestion d'erreurs

- Fichier absent / JSON invalide → message clair, code retour 1.
- Champs manquants dans un événement → valeurs par défaut (`.get`),
  événement non bloquant.
- `details` absent ou null → `{}`.

## 8. Tests

`tests/test_investigation.py` (unittest, TDD) :
- jeu synthétique : 2 IP de spraying (une aboutit), une force brute
  externe, un faux positif compte de service interne, mouvement latéral
  du compte créé, pas de 1102 ;
- tests unitaires par étape + test de bout en bout ;
- test anti-valeurs en dur : aucune valeur du jeu fourni dans
  `investigation.py` ;
- test de non-régression sur `logs_test.json` (IP, compte, host, tâche,
  compte créé attendus présents dans la sortie).

`tests/test_iocs.py` : extraction (dont regex hash/URL/domaine sur un
details synthétique), dédoublonnage, CSV MISP (en-tête, mapping), bundle
STIX (types, patterns, IDs stables d'une exécution à l'autre, refs du
report).

`tests/test_enrichissement_vt.py` (`urlopen` mocké, aucun appel réseau) :
succès, 404, 429 puis succès, 401, timeout, clé absente, IP RFC 5737 non
soumise, hit cache (pas d'appel HTTP), respect de l'intervalle (horloge
mockée).

## 9. Livrables

`investigation.py`, `iocs.py`, `enrichissement_vt.py`, `rapport_pdf.py`,
`sortie_rapport.txt`, `rapport_incident.pdf`, `iocs_misp.csv`,
`iocs_stix.json`, `NOTES.md` (5–10 lignes : seuils, limites dont IP
RFC 5737 et incohérence `result`, pistes).
