Tu trouveras en pièce-jointe le jeu de logs.
Egalement, je te joins le schéma du stage, et aussi un projet inspirant du stage qui peuvent t'aider pour l'exercice : https://dfirtnt.wordpress.com/2026/02/04/introducing-huntable-cti-studio/
Enfin, l'usage de l'IA est plus que recommandée, même obligatoire dans le cadre des attentes de l'exercice.

Si tu as la moindre question, je reste disponible.


Cahier d'exercice — Stage ForCERT : investigation automatisée en chaîne

1. Contexte et objectif
Tu dois écrire un script Python qui mène seul une investigation en plusieurs étapes chaînées. Il part d'une détection statistique et va jusqu'à un plan de remédiation. Chaque étape doit s'expliquer automatiquement.
Le contexte est fictif. L'entreprise ACME Industrie collecte les journaux Windows de ses postes et serveurs. On te remet une extraction d'une journée de logs au format JSON. L'équipe SOC soupçonne une activité malveillante sans savoir où chercher.
Ton script doit reproduire le raisonnement d'un analyste :
    1  . repérer une anomalie de connexion par statistique ;
    2. en déduire automatiquement les comptes et sessions concernés ;
    3. reconstituer ce qui s'est passé après la connexion ;
    4. produire un plan d'action adapté à ce qui a été trouvé.
Le résultat d'une étape doit alimenter automatiquement la requête de l'étape suivante. Aucune valeur (IP, compte, machine) ne doit être saisie à la main.
Important : ton script sera exécuté sur un second jeu de données que tu ne connais pas. Ce jeu a le même format, mais des machines, comptes, adresses, horaires et scénarios différents. Un script qui ne fonctionne que sur le fichier fourni ne remplit pas l'objectif.

2. Données fournies
Tu reçois un fichier logs_test.json. C'est une liste JSON d'objets, un objet par événement, triés par ordre chronologique. Chaque événement suit ce schéma :

Champ	Type	Description
timestamp	texte ISO 8601	Date et heure de l'événement (UTC), ex. 2026-03-12T08:14:05Z
event_id	entier	Identifiant d'événement Windows
host	texte	Nom du poste ou serveur, ex. WKS-014
account	texte	Compte concerné (TargetAccount ou SubjectAccount selon l'événement)
src_ip	texte ou null	IP source de la connexion, null si non applicable
logon_type	entier ou null	Type d'ouverture de session (voir ci-dessous), null si non applicable
result	texte	success ou failure
details	objet	Champs complémentaires selon l'événement (ligne de commande, processus parent, nom de tâche, groupe cible…)

Les event_id présents dans les données, et leur signification, sont les suivants. Tu peux t'y référer librement, c'est le référentiel officiel de l'exercice :
event_id	Signification	Champs utiles dans details
4624	Ouverture de session réussie	logon_type
4625	Échec d'ouverture de session	logon_type
4688	Création d'un processus	process, parent_process, command_line
4698	Création d'une tâche planifiée	task_name
4720	Création d'un compte utilisateur	new_account
4732	Ajout d'un membre à un groupe local	group, member
1102	Effacement du journal de sécurité	—


Types d'ouverture de session (logon_type) utiles : 2 ouverture interactive locale, 3 accès réseau (partage, authentification distante), 10 bureau à distance (RDP).

3. Travail demandé : quatre étapes chaînées
Le script enchîne quatre étapes. Chacune prend en entrée le résultat de la précédente et ne doit jamais s'appuyer sur une valeur écrite en dur.

Étape 1 — Détecter l'anomalie de connexion (statistique)
Parcours tous les échecs d'ouverture de session (event_id 4625) et regroupe-les par src_ip. Pour chaque IP, compte le nombre d'échecs et le nombre de comptes distincts visés. Retiens comme anomalie la ou les IP qui dépassent un seuil que tu définis et justifies, par exemple plus de 10 échecs sur au moins 5 comptes distincts. C'est le profil d'un password spraying.
Sortie de l'étape : la liste des IP suspectes, avec pour chacune le nombre d'échecs, le nombre de comptes visés, et la fenêtre horaire.

Étape 2 — Identifier la compromission réelle (pivot automatique)
Pour chaque IP suspecte trouvée à l'étape 1, cherche automatiquement s'il existe ensuite une ouverture de session réussie (event_id 4624) depuis cette même IP. Si oui, la tentative a abouti. Récupère le compte, le host et l'heure de cette connexion réussie.
Sortie de l'étape : pour chaque compromission confirmée, le triplet IP, compte, machine, ainsi que l'horodatage à partir duquel il faut regarder la suite.

Étape 3 — Reconstituer l'activité post-connexion (contexte)
À partir du compte et de la machine identifiés à l'étape 2, et à partir de l'heure de la connexion réussie, collecte tous les événements qui suivent sur cette machine, ou pour ce compte. Tu cherches la chaîne d'actions de l'attaquant : création de processus suspects (4688, par exemple un PowerShell lancé par Word), tâche planifiée (4698), création de compte (4720), ajout à un groupe privilégié (4732), effacement de journal (1102).
Sortie de l'étape : la chronologie ordonnée de ce qui s'est passé après l'intrusion, événement par événement.

Étape 4 — Proposer un plan d'action (remédiation)
En fonction des actions constatées à l'étape 3, génère un plan d'action. Le plan doit être conditionnel : chaque recommandation découle d'un fait observé. Si un compte a été créé, recommande sa désactivation en le nommant. Si une tâche planifiée a été posée, recommande de la supprimer en la nommant. Si le journal a été effacé, signale la perte de traçabilité. Inclus l'isolement de la machine et la réinitialisation des comptes concernés.
Sortie de l'étape : une liste d'actions concrètes, chacune reliée au fait qui la motive.

4. Explication automatique de chaque étape

L'exigence centrale : à chaque étape, le script écrit lui-même, en français clair, ce qu'il a cherché, ce qu'il a trouvé, et ce qu'il va faire ensuite. Un responsable non technique doit pouvoir lire la sortie et comprendre l'incident sans lire le code.

Concrètement, pour chaque étape, la sortie doit contenir une phrase de contexte (ce que je cherche), le résultat chiffré ou factuel (ce que je trouve), et la transition vers l'étape suivante (ce que j'en fais). Les valeurs citées doivent être celles réellement trouvées dans les données, jamais des exemples génériques.

Voici le format de sortie attendu, à adapter aux valeurs réelles :

=== ÉTAPE 1 : DÉTECTION D'ANOMALIE ===
Recherche des IP générant des échecs de connexion massifs (event 4625).
Résultat : l'IP 203.0.113.47 a provoqué 37 échecs sur 14 comptes distincts
entre 08:02 et 08:19. Ce profil correspond à du password spraying.
-> Je vais vérifier si cette IP a fini par réussir une connexion.

=== ÉTAPE 2 : CONFIRMATION DE COMPROMISSION ===
Recherche d'une connexion réussie (event 4624) depuis 203.0.113.47.
Résultat : connexion réussie à 08:21 avec le compte j.martin sur WKS-014.
La tentative a abouti.
-> Je vais reconstituer l'activité sur WKS-014 après 08:21.

=== ÉTAPE 3 : ACTIVITÉ POST-COMPROMISSION ===
Analyse des événements sur WKS-014 à partir de 08:21.
Résultat, chronologie :
  08:23  PowerShell lancé par winword.exe (exécution suspecte)
  08:25  tâche planifiée créée : \MicrosoftUpdateSync
  08:27  compte local créé : svc_backup
  08:28  svc_backup ajouté au groupe Administrateurs
  08:31  journal de sécurité effacé
-> Je vais produire le plan de remédiation correspondant.

=== ÉTAPE 4 : PLAN D'ACTION ===
Faits → actions :
  - Connexion attaquant confirmée -> isoler WKS-014 du réseau
  - Compte j.martin compromis -> forcer la réinitialisation du mot de passe
  - Compte svc_backup créé par l'attaquant -> le désactiver immédiatement
  - Tâche \MicrosoftUpdateSync -> la supprimer (persistance)
  - Journal effacé -> traçabilité locale perdue, s'appuyer sur le SIEM central

Le format exact est libre. Ce qui compte : les trois temps (recherche, résultat, transition) à chaque étape, et des valeurs réelles.

5. Contraintes, livrables et durée

Écris en Python 3, avec la bibliothèque standard uniquement (json, datetime, collections). pandas est autorisé si tu préfères, mais pas requis. Le script prend le chemin du fichier JSON en argument ou en constante clairement identifiée en haut du fichier, de sorte qu'on puisse le relancer sur un autre fichier en changeant une seule ligne.
Le code doit tourner tel quel sur un second fichier de même format sans aucune modification des valeurs. Les seuils et la logique sont paramétrés en haut du script, pas dispersés dans le code.
Livrables attendus :
    1. le script Python ; // avec des commentaires
    2. la sortie texte produite sur le fichier de test fourni ;
    3. cinq à dix lignes expliquant tes choix : seuils retenus, limites, ce que tu ferais avec plus de temps.

6. Bonus simples
Bonus facultatifs, dans l'ordre de valeur :
    - gérer le cas où plusieurs IP sont suspectes et plusieurs machines compromises, pas seulement une ;
    - distinguer un vrai spraying d'un faux positif, par exemple un compte de service dont le mot de passe a expiré et qui échoue en boucle depuis une IP interne sur un seul compte ;
    - rendre le seuil adaptatif plutôt que fixe, en se basant sur la moyenne observée ;
    - exporter le rapport final en fichier pdf, base toi sur la charte graphique de ce document /home/ubuntu/Bureau/CTI/Exercice de test/exemple charte graphique.pdf

7. Bonus avancés — detection engineering et CTI
Ces quatre pistes s'adressent aux candidats à l'aise. Elles prolongent le script de base et suivent le même esprit : chaînage automatique, explication de chaque résultat, valeurs tirées des données et jamais écrites en dur. Aucune n'est obligatoire ; elles se notent en points supplémentaires.
Règles de détection Splunk (SIGMA ou from scratch)
À partir des comportements repérés, le candidat propose une ou plusieurs règles de détection au format Splunk (SPL). Deux voies sont acceptées : partir d'une règle officielle du dépôt SigmaHQ (github.com/SigmaHQ/sigma) et la convertir vers le backend Splunk avec sigma-cli (pySigma), en citant la règle source ; ou écrire la règle de zéro. Au moins une règle doit couvrir le password spraying de l'étape 1, par exemple :
index=windows EventCode=4625
| bin _time span=5m
| stats dc(TargetUserName) as comptes, count as tentatives by _time, IpAddress
| where comptes > 10
Une seconde règle peut cibler la chaîne Word vers PowerShell, la création de compte suivie d'un ajout au groupe Administrateurs, ou l'effacement du journal (EventCode 1102). Pour chaque règle, on attend la logique, le faux positif anticipé et l'action de tri. On évalue la pertinence, pas la syntaxe parfaite.
Livrable Word automatisé
Le script génère un rapport d'incident au format Word (.docx), par exemple via python-docx, destiné à un responsable non technique. Le rapport reprend les quatre étapes expliquées, un tableau des IOC, la chronologie de l'intrusion et le plan d'action. Le document doit être lisible seul, sans le code ni la sortie console. C'est l'occasion de transformer la sortie texte en livrable présentable.
Extraction et enrichissement des IOC
Le candidat extrait automatiquement les IOC des données : IP source de l'attaque, comptes créés par l'attaquant, noms de tâches planifiées, lignes de commande et éventuels hachages. Il enrichit ensuite chaque IOC via au moins une source de threat intelligence : VirusTotal, URLScan, AlienVault OTX ou AbuseIPDB. L'intérêt est l'ingénierie : clé d'API hors du code (variable d'environnement), gestion du rate limiting, des erreurs et des retries, cache pour ne pas réinterroger deux fois la même valeur, et comportement propre quand la source ne renvoie rien.
Note : les IOC du jeu de test sont des valeurs de documentation (plages RFC 5737, base64 factice) ; elles ne remonteront rien sur les plateformes publiques. Un bon candidat le remarque et le dit. On ne juge pas le verdict obtenu mais la robustesse du pipeline. Rappel de prudence attendu : ne jamais téléverser un fichier ou un échantillon client sur un bac à sable public sans autorisation.
Injection dans MISP (CSV)
Le candidat produit un fichier CSV des IOC prêt à importer dans MISP. Le format attendu suit les attributs MISP, une ligne par IOC :
value,type,category,to_ids,comment
203.0.113.47,ip-src,Network activity,1,IP source du password spraying
svc_backup,windows-service-name,Persistence,0,Compte créé par l'attaquant
\MicrosoftUpdateSync,text,Persistence,0,Tâche planifiée de persistance

Le mapping type et catégorie doit être cohérent avec le genre d'IOC. Bonus dans le bonus : regrouper les IOC d'un même incident sous un même événement MISP
