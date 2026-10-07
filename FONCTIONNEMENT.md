# Fonctionnement de `investigation.py`

Ce document explique comment le script est construit et comment les étapes s'enchaînent. Pour l'usage et les choix (seuils, limites), voir `NOTES.md`.

## Vue d'ensemble

```
logs.json
   │  charger_logs()                      → list[Evenement]
   ▼
Étape 1  etape1_detection()               → ResultatDetection  (IP suspectes / écartées)
   ▼
Étape 2  etape2_pivot()                   → ResultatPivot      (compromissions : IP, compte, machine, t0)
   ▼
Étape 3  etape3_chronologie()             → list[Chronologie]  (événements après t0, qualifiés)
   ▼
Étape 4  etape4_plan() + evaluer_gravite() → list[Action], gravité
   ▼
Étape 5  extraire_iocs() [+ enrichir_iocs()] → list[IOC]  (+ verdicts VirusTotal)
   ▼
rapport_texte()  ·  exporter_misp_csv() / exporter_stix()  ·  generer_docx()
```

La fonction `investiguer(chemin, enrichir)` enchaîne les cinq étapes. **Chaque étape ne reçoit que le résultat de la précédente** : aucune IP, aucun compte ni aucune machine n'est écrit dans le code. Les étapes sont des fonctions pures qui renvoient des structures de données (`dataclass`). Le texte explicatif est produit à part, par une fonction `expliquer_etapeN()` par étape, à partir de ces structures : le rapport texte et le rapport Word s'appuient ainsi sur les mêmes faits.

## Organisation du fichier

| Section | Rôle |
|---|---|
| **Paramètres** (en tête) | Fichier de logs par défaut, seuils, réseaux internes, codes d'événement, listes de référence (processus bureautiques, interpréteurs, marqueurs suspects, groupes à privilèges), noms des fichiers de sortie, réglages VirusTotal. C'est le seul endroit à modifier pour adapter le comportement. |
| **Modèle et chargement** | Classe `Evenement` et `charger_logs()`. |
| **Étapes 1 à 5** | Une section par étape : la fonction de calcul, puis sa fonction d'explication. |
| **Enchaînement et rapport** | `investiguer()`, `rapport_texte()`, données du rapport Word, `main()` (ligne de commande). |

Modules associés : `iocs.py` (extraction des IOC, exports MISP et STIX), `enrichissement_vt.py` (client VirusTotal), `rapport_word.py` (mise en page Word), `affichage.py` (aides d'affichage).

## Chargement des logs

`charger_logs(chemin)` lit le JSON et construit une liste d'`Evenement` **triée par date**, sans faire confiance à l'ordre du fichier.

- Les dates sont converties en UTC, quel que soit leur format (`Z`, `+02:00`, fractions de seconde).
- Les champs absents ou nuls reçoivent une valeur par défaut ; `details: null` devient `{}`.
- Une IP source vide ou égale à `"-"` (valeur nulle de Windows) devient `None`.
- Un événement sans date exploitable est ignoré.
- Un fichier absent, illisible ou qui n'est pas une liste JSON lève `ErreurChargement` avec un message en français.

Les noms de compte et de machine sont comparés **sans tenir compte de la casse**, comme sous Windows (`_cle()`, `_dans()`), en affichant la première écriture rencontrée.

## Étape 1 — Détection (`etape1_detection`)

**Entrée** : tous les événements.
**Traitement** :
1. On retient les échecs de connexion par leur code `event_id == 4625`, sans se fier au champ `result`, qui est incohérent dans le jeu fourni.
2. Pour chaque IP source, on compte les échecs, les comptes distincts visés, les machines visées et la fenêtre horaire. Les échecs sans IP sont comptés à part et signalés.
3. `_classer()` attribue un profil à chaque IP :

| Profil | Règle | Suite |
|---|---|---|
| `spraying` | ≥ `SEUIL_ECHECS` échecs et ≥ `SEUIL_COMPTES` comptes | suspecte |
| `force_brute` | ≥ `SEUIL_ECHECS` échecs, peu de comptes, IP externe | suspecte |
| `faux_positif_probable` | ≥ `SEUIL_ECHECS` échecs sur un seul compte, IP interne | écartée, avec motif |
| `sous_seuil` | le reste | ignorée, ou écartée si nombreux échecs |

« Interne » signifie appartenir à `RESEAUX_INTERNES` (plages RFC 1918), testé par `est_interne()`. On n'utilise pas `ipaddress.is_private`, qui considère aussi comme privées les plages de documentation (RFC 5737) utilisées dans le jeu de test.

**Sortie** : `ResultatDetection` (IP suspectes triées par date, IP écartées, seuils réellement appliqués).

## Étape 2 — Pivot (`etape2_pivot`)

**Entrée** : les IP suspectes de l'étape 1.
**Traitement** : pour chaque IP, on cherche les connexions réussies (4624) depuis cette IP **après son premier échec**. Chaque couple (compte, machine) distinct donne une `Compromission`, datée de sa première connexion réussie (`t0`). Une IP sans connexion réussie est classée « tentative non aboutie ».
**Sortie** : `ResultatPivot` (compromissions et IP non abouties).

## Étape 3 — Chronologie (`etape3_chronologie`)

**Entrée** : les compromissions de l'étape 2.
**Traitement** : pour chaque compromission, on parcourt les événements à partir de `t0` et on retient ceux qui :
- ont lieu sur la machine compromise ;
- **ou** sont faits par un compte suivi ;
- **ou** ajoutent un compte suivi à un groupe (4732).

Au départ, le seul compte suivi est le compte compromis. **Tout compte créé par l'attaquant (4720) est suivi à son tour**, ce qui permet de détecter un rebond vers une autre machine.

`qualifier_evenement()` donne à chaque événement une nature et une description en français :

| Événement | Qualification |
|---|---|
| 4688 (processus) | **suspect** si un logiciel bureautique lance un interpréteur (Word → PowerShell), si la ligne de commande contient un marqueur (`-enc`, `-nop`, `hidden`, `iex`, `downloadstring`, `bypass`…) ou si la commande vient d'un compte suivi ; la commande encodée est décodée automatiquement (`decoder_commande()`, base64 en UTF-16LE) |
| 4698 | tâche planifiée (persistance) |
| 4720 | création de compte |
| 4732 | ajout à un groupe, critique si le groupe est dans `GROUPES_PRIVILEGIES` |
| 1102 | effacement du journal de sécurité |
| 4624 | connexion initiale, nouvelle connexion depuis l'IP d'attaque, rebond vers une autre machine (connexion réseau ou RDP), ou connexion interactive « à vérifier » |

Les marqueurs sont comparés **comme des mots entiers**, et non comme des bouts de texte, pour éviter les faux positifs (`iexplore.exe` ne déclenche pas `iex`, et `-nopause` n'est pas `-nop`).

**Sortie** : une `Chronologie` par compromission (événements qualifiés et comptes suivis).

## Étape 4 — Plan d'action (`etape4_plan`, `evaluer_gravite`)

**Entrée** : les résultats des étapes 1 à 3.
**Traitement** : chaque action est créée **à partir d'un fait observé** et nomme l'objet concerné :

| Fait | Action | Priorité |
|---|---|---|
| IP suspecte | bloquer l'IP | immédiat |
| Compromission | isoler la machine, réinitialiser le mot de passe du compte | immédiat |
| Compte créé | le désactiver | immédiat |
| Ajout à un groupe à privilèges | retirer le compte du groupe | immédiat |
| Rebond | isoler la machine secondaire | immédiat |
| Tâche planifiée | la supprimer | court terme |
| Commande suspecte | collecter les preuves, analyser la commande | court terme |
| Journal effacé | traçabilité perdue, s'appuyer sur le SIEM | court terme |
| Faux positif, tentative non aboutie | vérifier le compte de service, surveiller les comptes visés | suivi |

Les actions identiques sont dédoublonnées et triées par priorité. La gravité vaut **CRITIQUE** s'il y a ajout à un groupe à privilèges, effacement du journal ou rebond ; **ÉLEVÉE** s'il y a compromission ; **MODÉRÉE** si une attaque n'a pas abouti ; **FAIBLE** sinon. Sa justification cite les faits observés.

## Étape 5 — IOC (`iocs.py`, `enrichissement_vt.py`)

**Entrée** : les résultats des étapes 1 à 3.
**Traitement** :
- `extraire_iocs()` collecte les indicateurs : IP d'attaque, comptes et machines compromis, comptes créés, tâches planifiées, commandes suspectes. Les URL, domaines, IP et empreintes ne sont extraits **que des événements porteurs d'un marqueur suspect** ; les IP internes sont exclues.
- Avec `--enrichir`, `enrichir_iocs()` interroge VirusTotal **en direct**, sans cache disque. La clé est lue dans la variable d'environnement `VT_API_KEY`. Le client ne fait que consulter des valeurs, sans jamais téléverser de fichier, et n'envoie pas les IP non routables (privées ou de documentation). Il respecte 15 s entre deux requêtes, réessaie après une erreur 429 et s'arrête proprement si la clé est refusée.
- Pour chaque IOC connu de VirusTotal, le rapport affiche le pays, l'opérateur réseau, le résultat des analyses, les moteurs qui le signalent, la réputation et le lien vers la fiche.

**Sortie** : la liste des IOC, exportée en CSV pour MISP (`iocs_misp.csv`) et en bundle STIX 2.1 (`iocs_stix.json`, identifiants stables d'une exécution à l'autre).

## Explications et rapports

- `expliquer_etape1()` à `expliquer_etape5()` rédigent chaque étape en trois temps : **Recherche** (ce que je cherche), **Résultat** (ce que je trouve, avec les valeurs réelles), **->** (ce que j'en fais).
- `rapport_texte()` assemble l'en-tête (fichier, nombre d'événements, période, gravité) et les cinq explications : c'est le contenu affiché et écrit dans `sortie_rapport.txt`.
- `construire_donnees_rapport()` prépare un dictionnaire déjà rédigé (synthèse en trois phrases, étapes, chronologie, plan, IOC, détail VirusTotal), que `rapport_word.py` met en page dans `rapport_incident.docx`.

## Ligne de commande (`main`)

```bash
python3 investigation.py [logs.json] [--enrichir]
```

1. lit les arguments (fichier par défaut : `FICHIER_LOGS`) ;
2. lance `investiguer()` ;
3. affiche le rapport et écrit `sortie_rapport.txt`, `iocs_misp.csv`, `iocs_stix.json` et `rapport_incident.docx` dans le dossier courant ;
4. renvoie le code **0** en cas de succès et **1** si le fichier de logs est inexploitable ou si l'écriture d'un fichier échoue (message en français, sans trace d'erreur Python). Si python-docx est absent, les autres fichiers sont tout de même produits.

## Tests

`python3 -m unittest discover -s tests` exécute les tests :
- chaque étape est vérifiée séparément sur un jeu synthétique dont le scénario diffère du jeu fourni (`tests/jeu_synthetique.py`) ;
- un test de bout en bout et un test de non-régression portent sur `logs_test.json` ;
- un test vérifie qu'aucune valeur du jeu fourni n'est écrite dans le code ;
- VirusTotal est simulé, aucun appel réseau n'est fait.
