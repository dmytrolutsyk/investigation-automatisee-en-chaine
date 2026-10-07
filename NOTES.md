# Notes de conception

Usage (Python ≥ 3.11) : `python3 investigation.py logs_test.json [--enrichir]` (rapport Word `rapport_incident.docx`) (clé VirusTotal via la variable d'environnement `VT_API_KEY`).

- **Seuils** : 10 échecs (4625) par IP pour la signaler, 5 comptes distincts pour parler de spraying. Le spraying vise beaucoup de comptes avec peu d'essais chacun, ce qui évite le verrouillage ; le nombre de comptes est donc le bon discriminant, pas le volume.
- **Trois profils** : password spraying, force brute (un compte, beaucoup d'essais), et faux positif interne (compte de service dont le mot de passe a expiré). L'« interne » vient de `RESEAUX_INTERNES` (RFC 1918), pas de `ipaddress.is_private`, qui classe aussi les plages RFC 5737 de documentation comme privées.
- **Incohérence des logs** : des 4625 portent `result="success"` ; l'identifiant d'événement fait foi, le rapport le signale.
- **VirusTotal** : les IP du jeu sont en RFC 5737 (documentation), VT ne peut rien en dire, elles sont marquées « non soumises ». Ce qui compte est le pipeline : interrogation en direct (sans cache disque), limitation de débit, retry sur 429, clé lue dans l'environnement, consultation seule (aucun fichier envoyé).
- **Limites** : seuils fixes, pas de fenêtre temporelle glissante ; périmètre suivi = machine compromise + compte + comptes créés par l'attaquant ; pas de corrélation Kerberos (4768/4771) ; IOC réseau (URL, domaines, IP) tirés des seuls événements suspects porteurs d'un marqueur (pas des commandes sans marqueur d'un compte suivi), IP internes exclues ; extraction des domaines « nus » limitée à une liste de TLD connus (compromis : moins de faux IOC, mais des domaines rares peuvent être manqués).
- **Avec plus de temps** : seuil adaptatif (écart à la moyenne), fenêtres glissantes, règles Sigma/SPL, import automatique dans OpenCTI/MISP, rapport Word.
- **Usage de l'IA** : Claude Code a servi à la conception, l'implémentation et la relecture ; chaque résultat a été vérifié par des tests (`python3 -m unittest discover -s tests`).
