"""Aides d'affichage du rapport Word (bibliothèque standard seule)."""
import re

# Au-delà, un texte (ligne de commande encodée…) est tronqué à l'affichage : une
# cellule ou une ligne de carte ne peut pas dépasser la hauteur d'une page.
LIMITE_AFFICHAGE = 800
LIMITE_JETON = 120   # un jeton sans espace (base64…) est raccourci, la suite reste lisible
JETON_LONG = re.compile(r"\S{%d,}" % (LIMITE_JETON + 1))
SUFFIXE_TRONQUE = (" … [tronqué pour l'affichage : valeur complète dans le rapport texte "
                   "et l'export MISP]")


def tronquer(valeur, limite: int = LIMITE_AFFICHAGE) -> str:
    """Texte tronqué pour l'affichage (flèche -> ASCII, jetons longs et texte capés)."""
    texte = str(valeur).replace("→", "->").replace("\u200b", "")
    texte = JETON_LONG.sub(lambda m: m.group(0)[:LIMITE_JETON] + "…[tronqué]", texte)
    if len(texte) > limite:
        texte = texte[:limite] + SUFFIXE_TRONQUE
    return texte

PRUDENCE = ("Rappel de prudence : ces indicateurs proviennent d'une analyse automatisée. "
            "Faites-les valider par l'équipe sécurité avant de les bloquer ou de les "
            "partager, et ne soumettez jamais de fichier interne à un service en ligne.")

# Lignes des étapes : préfixe du texte brut -> libellé affiché
LIBELLES = (("Recherche :", "Ce que l'on cherche :"), ("Résultat :", "Ce que l'on trouve :"),
             ("->", "Conclusion :"), ("Note :", "Note :"))
EN_TETE_PRIORITE = re.compile(r"^[A-ZÉÈ ]+ :$")
# Étape 5 condensée : le décompte par type MISP est remplacé par le seul total
# (l'annexe donne les types en clair).
DECOMPTE_IOC = re.compile(r"^(Résultat : \d+ IOC) : .*$")
