"""Rapport d'incident PDF (reportlab platypus, A4), inspiré de la charte Formind.

Ce module ne fait que la mise en page : les textes arrivent déjà rédigés dans
le dictionnaire produit par investigation.construire_donnees_rapport.
"""
import re
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (CondPageBreak, Flowable, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

# --- Charte -----------------------------------------------------------------
MARINE = colors.HexColor("#1B2A4A")
TURQUOISE = colors.HexColor("#1FA3A8")
FOND_CARTE = colors.HexColor("#F2F7F8")
BORD_CARTE = colors.HexColor("#C9DCE0")
LIGNE_ALTERNEE = colors.HexColor("#E6F1F3")
TEXTE = colors.HexColor("#22303C")
GRIS = colors.HexColor("#6B7A86")
ALERTE = colors.HexColor("#C0392B")
FOND_ALERTE = colors.HexColor("#FBEAE8")
COULEURS_GRAVITE = {"CRITIQUE": "#C0392B", "ÉLEVÉE": "#E67E22",
                    "MODÉRÉE": "#F1C40F", "FAIBLE": "#27AE60"}
COULEURS_PRIORITE = {"IMMÉDIAT": "#C0392B", "COURT TERME": "#E67E22", "SUIVI": "#1FA3A8"}
POLICE, POLICE_GRAS, POLICE_ITALIQUE = "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"

MARGE = 18 * mm
LARGEUR_UTILE = A4[0] - 2 * MARGE
# Au-delà, un texte (ligne de commande encodée…) est tronqué à l'affichage : une
# cellule ou une ligne de carte ne peut pas dépasser la hauteur d'une page.
LIMITE_AFFICHAGE = 800
LIMITE_JETON = 120   # un jeton sans espace (base64…) est raccourci, la suite reste lisible
JETON_LONG = re.compile(r"\S{%d,}" % (LIMITE_JETON + 1))
SUFFIXE_TRONQUE = (" … [tronqué pour l'affichage : valeur complète dans le rapport texte "
                   "et l'export MISP]")
PRUDENCE = ("Rappel de prudence : ces indicateurs proviennent d'une analyse automatisée. "
            "Faites-les valider par l'équipe sécurité avant de les bloquer ou de les "
            "partager, et ne soumettez jamais de fichier interne à un service en ligne.")


# --- Texte ------------------------------------------------------------------
def _txt(valeur, limite: int = LIMITE_AFFICHAGE) -> str:
    """Texte sûr pour Paragraph : tronqué, caractères hors police remplacés, échappé."""
    texte = str(valeur).replace("→", "->").replace("\u200b", "")
    texte = JETON_LONG.sub(lambda m: m.group(0)[:LIMITE_JETON] + "…[tronqué]", texte)
    if len(texte) > limite:
        texte = texte[:limite] + SUFFIXE_TRONQUE
    texte = texte.encode("cp1252", "replace").decode("cp1252")  # polices standard : WinAnsi
    return escape(texte)


def _style(nom, **kw) -> ParagraphStyle:
    base = dict(fontName=POLICE, fontSize=9.5, leading=13, textColor=TEXTE)
    base.update(kw)
    return ParagraphStyle(nom, **base)


S_CORPS = _style("corps", alignment=TA_JUSTIFY)
S_SYNTHESE = _style("synthese", fontSize=11, leading=15.5, alignment=TA_JUSTIFY,
                    spaceAfter=4)
S_META = _style("meta", fontSize=9, textColor=GRIS, leading=12)
S_PUCE = _style("puce", leftIndent=12, bulletIndent=2, fontSize=9, leading=12.5)
S_PUCE2 = _style("puce2", leftIndent=24, bulletIndent=14, fontSize=8.5, leading=12)
S_EVENEMENT = _style("evenement", leftIndent=20, bulletIndent=2, fontSize=9, leading=12.5)
S_ALERTE = _style("alerte", leftIndent=20, bulletIndent=2, fontSize=9, leading=12.5,
                  backColor=FOND_ALERTE,
                  borderPadding=(1, 2, 1, 2), bulletFontName=POLICE_GRAS, bulletColor=ALERTE)
S_ACTION = _style("action", fontSize=10, leading=14, leftIndent=16, bulletIndent=2)
S_SOUS_TITRE = _style("soustitre", leftIndent=12, fontName=POLICE_GRAS, fontSize=9,
                      textColor=MARINE, spaceBefore=2)
S_NOTE = _style("note", fontName=POLICE_ITALIQUE, fontSize=8.5, leading=12, textColor=GRIS)
S_CELLULE = _style("cellule", fontSize=8, leading=10.2)
S_CELLULE_GRAS = _style("cellulegras", fontName=POLICE_GRAS, fontSize=8, leading=10.2)
S_ENTETE = _style("entete", fontName=POLICE_GRAS, fontSize=8.5, leading=10.5,
                  textColor=colors.white)
S_TITRE = _style("titre", fontName=POLICE_GRAS, fontSize=22, leading=27, textColor=MARINE)


# --- Éléments graphiques ----------------------------------------------------
class Pastille(Flowable):
    """Pastille arrondie (titre de section ou sous-titre), en dégradé discret."""

    def __init__(self, texte, couleurs, taille=11, hauteur=None, couleur_texte=colors.white,
                 largeur_min=0):
        super().__init__()
        self.texte = str(texte).encode("cp1252", "replace").decode("cp1252")
        self.couleurs, self.taille = couleurs, taille
        self.hauteur = hauteur or taille * 2
        self.couleur_texte = couleur_texte
        self.largeur = min(LARGEUR_UTILE, max(
            largeur_min, stringWidth(self.texte, POLICE_GRAS, taille) + self.hauteur * 1.4))

    def wrap(self, *_):
        return self.largeur, self.hauteur

    def draw(self):
        c, w, h = self.canv, self.largeur, self.hauteur
        c.saveState()
        chemin = c.beginPath()
        chemin.roundRect(0, 0, w, h, h / 2)
        c.clipPath(chemin, stroke=0, fill=0)
        if len(self.couleurs) > 1:
            c.linearGradient(0, 0, w, 0, self.couleurs, extend=True)
        else:
            c.setFillColor(self.couleurs[0])
            c.rect(0, 0, w, h, stroke=0, fill=1)
        c.restoreState()
        c.setFillColor(self.couleur_texte)
        c.setFont(POLICE_GRAS, self.taille)
        c.drawString(h * 0.7, (h - self.taille * 0.72) / 2, self.texte)


def _section(texte):
    """Titre de section : saut de page conditionnel puis pastille marine."""
    return [CondPageBreak(45 * mm), Spacer(1, 4 * mm),
            Pastille(texte, [MARINE, colors.HexColor("#24607A")], taille=10.5),
            Spacer(1, 2.5 * mm)]


def _carte(paragraphes, fond=FOND_CARTE, bord=BORD_CARTE):
    """Carte arrondie à fond clair ; une ligne par paragraphe pour pouvoir la scinder."""
    lignes = [[p] for p in paragraphes] or [[Paragraph("", S_CORPS)]]
    t = Table(lignes, colWidths=[LARGEUR_UTILE], cornerRadii=[6, 6, 6, 6])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), fond),
        ("BOX", (0, 0), (-1, -1), 0.8, bord),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("TOPPADDING", (0, 0), (-1, 0), 8), ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
    ]))
    return t


def _tableau(entetes, lignes, largeurs_mm, styles_colonnes=None, alertes=()):
    """Tableau : en-tête marine texte blanc, lignes alternées, en-tête répété.

    largeurs_mm : une largeur par colonne, None pour celle qui prend le reste.
    """
    styles_colonnes = styles_colonnes or {}
    donnees = [[Paragraph(_txt(e), S_ENTETE) for e in entetes]]
    for ligne in lignes:
        donnees.append([styles_colonnes.get(j, lambda v: Paragraph(_txt(v), S_CELLULE))(v)
                        for j, v in enumerate(ligne)])
    fixes = sum(l for l in largeurs_mm if l is not None) * mm
    largeurs = [LARGEUR_UTILE - fixes if l is None else l * mm   # None : colonne souple
                for l in largeurs_mm]
    t = Table(donnees, colWidths=largeurs, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), MARINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, MARINE),
    ]
    for i in range(1, len(donnees)):
        fond = LIGNE_ALTERNEE if i % 2 == 0 else colors.white
        if i - 1 in alertes:   # index des lignes à surligner en rouge
            fond = FOND_ALERTE
        style.append(("BACKGROUND", (0, i), (-1, i), fond))
    t.setStyle(TableStyle(style))
    return t


def _badge_gravite(gravite):
    fond = colors.HexColor(COULEURS_GRAVITE.get(gravite, "#6B7A86"))
    texte = MARINE if gravite == "MODÉRÉE" else colors.white
    return Pastille(f"GRAVITÉ : {gravite}", [fond], taille=13, hauteur=26,
                    couleur_texte=texte)


# --- Textes des étapes -------------------------------------------------------
_LIBELLES = (("Recherche :", "Ce que l'on cherche :"), ("Résultat :", "Ce que l'on trouve :"),
             ("->", "Conclusion :"), ("Note :", "Note :"))
_EN_TETE_PRIORITE = re.compile(r"^[A-ZÉÈ ]+ :$")
# Étape 5 condensée : le décompte par type MISP est remplacé par le seul total
# (l'annexe donne les types en clair).
_DECOMPTE_IOC = re.compile(r"^(Résultat : \d+ IOC) : .*$")


def _ligne_etape(ligne: str, condense: bool):
    """Paragraphe pour une ligne d'explication, ou None si elle est omise."""
    retrait = len(ligne) - len(ligne.lstrip(" "))
    brut = ligne.strip()
    if not brut:
        return None
    if retrait == 0:
        if condense:
            brut = _DECOMPTE_IOC.sub(r"\1.", brut)
        for prefixe, libelle in _LIBELLES:
            if brut.startswith(prefixe):
                reste = brut[len(prefixe):].strip()
                couleur = TURQUOISE.hexval()[2:] if prefixe != "Note :" else "6B7A86"
                style = S_NOTE if prefixe == "Note :" else S_CORPS
                return Paragraph(f'<font name="{POLICE_GRAS}" color="#{couleur}">'
                                 f'{_txt(libelle)}</font> {_txt(reste)}', style)
        return Paragraph(_txt(brut), S_CORPS)
    if condense and (brut.startswith("- ") or _EN_TETE_PRIORITE.match(brut)):
        return None   # détail repris dans le tableau qui suit l'étape
    if _EN_TETE_PRIORITE.match(brut):
        return Paragraph(_txt(brut), S_SOUS_TITRE)
    if brut.startswith("[!]"):
        texte = _txt(brut[3:].strip()).replace("  ", "&nbsp;&nbsp; ")
        return Paragraph(texte, S_ALERTE, bulletText="[!]")
    style = S_PUCE2 if retrait >= 4 else S_PUCE
    texte = brut[2:] if brut.startswith("- ") else brut
    if retrait >= 4 and not brut.startswith("- "):   # événement non suspect (étape 3)
        return Paragraph(_txt(texte).replace("  ", "&nbsp;&nbsp; "), S_EVENEMENT,
                         bulletText="•")
    return Paragraph(_txt(texte), style, bulletText="•" if brut.startswith("- ") else None)


def _etape(etape: dict, numero: int, condense: bool = False, renvoi: str = ""):
    titre = etape["titre"]
    titre = re.sub(r"^ÉTAPE\s+\d+\s*:\s*", "", titre)
    paragraphes = [p for p in (_ligne_etape(l, condense) for l in etape["texte"].splitlines())
                   if p is not None]
    if renvoi:
        paragraphes.append(Paragraph(_txt(renvoi), S_NOTE))
    elements = _section(f"Étape {numero} · {titre}")
    elements.append(_carte(paragraphes))
    return elements


# --- Pied de page ------------------------------------------------------------
def _fabrique_canvas(genere_le: str):
    """Canvas qui numérote « page N / total » et dessine le pied de page."""

    class CanvasNumerote(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for etat in self._pages:
                self.__dict__.update(etat)
                self._pied(total)
                super().showPage()
            super().save()

        def _pied(self, total):
            largeur = A4[0]
            self.saveState()
            self.setStrokeColor(TURQUOISE)
            self.setLineWidth(0.8)
            self.line(MARGE, 12 * mm, largeur - MARGE, 12 * mm)
            self.setFont(POLICE, 7.5)
            self.setFillColor(GRIS)
            texte = f"Document généré automatiquement le {genere_le} – ForCERT"
            self.drawString(MARGE, 8 * mm, texte.encode("cp1252", "replace").decode("cp1252"))
            self.drawRightString(largeur - MARGE, 8 * mm,
                                 f"Page {self._pageNumber} / {total}")
            self.restoreState()

    return CanvasNumerote


# --- Document ---------------------------------------------------------------
def generer_pdf(chemin: str, donnees: dict) -> None:
    """Écrit le rapport d'incident PDF (A4) à partir de construire_donnees_rapport."""
    doc = SimpleDocTemplate(
        chemin, pagesize=A4, leftMargin=MARGE, rightMargin=MARGE, topMargin=MARGE,
        bottomMargin=MARGE, title=donnees["titre"], author="ForCERT",
        subject="Rapport d'incident généré automatiquement")
    h = []

    # Page 1 : synthèse pour le décideur
    h.append(Paragraph(_txt(donnees["titre"]), S_TITRE))
    h.append(Spacer(1, 2 * mm))
    h.append(Pastille("Investigation automatisée des journaux Windows",
                      [TURQUOISE, colors.HexColor("#178A8F")], taille=12))
    h.append(Spacer(1, 4 * mm))
    meta = [f"Période analysée : du {donnees['periode']}" if donnees["periode"][:1].isdigit()
            else f"Période analysée : {donnees['periode']}"]
    if donnees.get("fichier"):
        n = donnees.get("nb_evenements", 0)
        meta.append(f"Source : {donnees['fichier']} ({n} événement{'s' if n > 1 else ''}) "
                    f"· heures en UTC")
    for m in meta:
        h.append(Paragraph(_txt(m), S_META))
    h.append(Spacer(1, 5 * mm))
    h.append(_badge_gravite(donnees["gravite"]))

    h += _section("En bref")
    h.append(_carte([Paragraph(_txt(p), S_SYNTHESE) for p in donnees["synthese"]]))

    h += _section("Actions à lancer immédiatement")
    actions = donnees["actions_prioritaires"]
    if actions:
        paragraphes = [Paragraph(_txt(a), S_ACTION, bulletText=f"{i}.")
                       for i, a in enumerate(actions, 1)]
    else:
        paragraphes = [Paragraph("Aucune action immédiate n'est nécessaire.", S_CORPS)]
    h.append(_carte(paragraphes))
    h.append(Spacer(1, 3 * mm))
    h.append(Paragraph(
        "Les pages suivantes détaillent le raisonnement suivi, étape par étape, la "
        "chronologie de l'attaque, le plan d'action complet et, en annexe, les "
        "indicateurs techniques à transmettre à l'équipe sécurité.", S_NOTE))
    h.append(PageBreak())

    # Déroulé de l'investigation
    etapes = donnees["etapes"]
    for i, etape in enumerate(etapes[:3], 1):
        h += _etape(etape, i)

    h += _section("Chronologie de l'attaque")
    if donnees["chronologie"]:
        lignes = [[heure, machine, compte, desc[4:] if desc.startswith("[!] ") else desc]
                  for heure, machine, compte, desc in donnees["chronologie"]]
        suspects = {i for i, brut in enumerate(donnees["chronologie"])
                    if brut[3].startswith("[!] ")}
        large = any(len(l[0]) > 5 for l in lignes)
        h.append(_tableau(["Heure", "Machine", "Compte", "Ce qui s'est passé"], lignes,
                          [21 if large else 13, 26, 24, None],
                          {0: lambda v: Paragraph(_txt(v), S_CELLULE_GRAS)},
                          alertes=suspects))
        h.append(Spacer(1, 1.5 * mm))
        h.append(Paragraph("Les actions suspectes sont surlignées en rouge.", S_NOTE))
    else:
        h.append(_carte([Paragraph("Aucune activité d'attaquant à retracer.", S_CORPS)]))

    if len(etapes) > 3:
        h += _etape(etapes[3], 4, condense=True,
                    renvoi="Le détail des actions figure dans le tableau ci-dessous.")
    h += _section("Plan d'action")
    if donnees["plan"]:
        def priorite(v):
            couleur = COULEURS_PRIORITE.get(v, "#1B2A4A")
            return Paragraph(f'<font color="{couleur}">{_txt(v)}</font>', S_CELLULE_GRAS)
        h.append(_tableau(["Fait observé", "Action à mener", "Priorité"], donnees["plan"],
                          [70, None, 27], {2: priorite}))
    else:
        h.append(_carte([Paragraph("Aucune action à mener.", S_CORPS)]))

    if len(etapes) > 4:
        h += _etape(etapes[4], 5, condense=True,
                    renvoi="La liste des indicateurs figure dans l'annexe ci-dessous.")
    h += _section("Annexe · Indicateurs de compromission (IOC)")
    if donnees["iocs"]:
        h.append(_tableau(["Indicateur", "Type", "Vérification VirusTotal"], donnees["iocs"],
                          [88, 32, None]))
    else:
        h.append(_carte([Paragraph("Aucun indicateur extrait.", S_CORPS)]))
    h.append(Spacer(1, 3 * mm))
    h.append(_carte([Paragraph(_txt(PRUDENCE), S_NOTE)], fond=colors.HexColor("#FFF8E6"),
                    bord=colors.HexColor("#F1C40F")))

    doc.build(h, canvasmaker=_fabrique_canvas(donnees["genere_le"]))
