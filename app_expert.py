from __future__ import annotations

import hashlib
import hmac
import os
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
import smtplib
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from io import BytesIO

import streamlit as st

try:
    import pdfplumber
except ImportError:
    st.error("❌ pdfplumber non installé. Lancez : pip install -r requirements.txt")
    st.stop()

try:
    import pikepdf
except ImportError:
    st.error("❌ pikepdf non installé. Lancez : pip install -r requirements.txt")
    st.stop()

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Flowable, KeepTogether)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib import colors
    from reportlab.lib.colors import HexColor
    from reportlab.pdfgen import canvas as rl_canvas
except ImportError:
    st.error("❌ reportlab non installé. Lancez : pip install -r requirements.txt")
    st.stop()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============== MODÈLES DE DONNÉES ==============

@dataclass
class AppSecrets:
    email_expediteur: str
    mot_de_passe_email: str


@dataclass
class PDFAnalysis:
    texte: str
    metadata: dict
    raw_bytes: bytes                 # conservés pour l'analyse structurelle
    hash_sha256: str                 # VRAI hash du fichier
    error: Optional[str] = None


@dataclass
class MathResult:
    est_scan: bool
    ecart: float
    calcul_theorique: float
    net_imposable_mensuel: float
    mois_cumules: int
    cumul_imposable: float
    fraude_math: bool


@dataclass
class ForensicResult:
    hash_sha256: str                 # VRAI hash du fichier (pas des métadonnées)
    incremental_updates: int         # nombre de sauvegardes successives (%%EOF)
    xref_anormal: bool               # mises à jour non expliquées par une signature électronique
    fraude_meta: bool
    signature_detectee: bool = False  # /ByteRange présent = document signé électroniquement
    logiciels_detectes: List[str] = field(default_factory=list)
    date_modifiee: bool = False      # ModDate != CreationDate
    javascript_suspect: bool = False
    fichiers_incorpores: bool = False
    annotations_suspectes: bool = False
    fonts_detectees: List[str] = field(default_factory=list)
    score_risque_forensic: int = 0


@dataclass
class Verdict:
    score_risque: int
    statut: str
    date_analyse: str


@dataclass
class DocumentAnalyse:
    """Résultat complet pour UN document au sein d'un dossier (1 à 4 pièces)."""
    nom_fichier: str
    type_document: str
    analysis: "PDFAnalysis"
    forensic: "ForensicResult"
    math: "MathResult"


@dataclass
class CrossDocResult:
    """Cohérence entre les documents d'un même dossier (formules Sécurisé / Dossier Complet)."""
    nb_documents: int
    doublons_detectes: bool = False
    fichiers_dupliques: List[str] = field(default_factory=list)
    ecarts_fiches_paie: List[str] = field(default_factory=list)  # messages informatifs
    incoherence_financiere: bool = False


TYPES_DOCUMENT = ["Fiche de paie", "Avis d'imposition", "Contrat de travail", "Autre"]

# Libellé affiché -> nombre de documents autorisés pour la formule
FORMULES = {
    "Essentiel (59 € — 1 document)": 1,
    "Sécurisé (129 € — jusqu'à 2 documents)": 2,
    "Dossier Complet (229 € — jusqu'à 4 documents)": 4,
}


# ============== EXTRACTION ==============

def extract_pdf_content(fichier_pdf) -> PDFAnalysis:
    """Extrait texte, métadonnées et VRAI hash du fichier. Conserve les octets bruts
    pour l'analyse structurelle (pikepdf + scan binaire)."""
    try:
        pdf_bytes = fichier_pdf.read()
        hash_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        texte = ""
        metadata_dict = {}

        with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
            if pdf.metadata:
                metadata_dict = {
                    "Auteur": str(pdf.metadata.get("Author", "N/A"))[:80],
                    "Créateur": str(pdf.metadata.get("Creator", "N/A"))[:80],
                    "Producteur": str(pdf.metadata.get("Producer", "N/A"))[:80],
                    "Date création": str(pdf.metadata.get("CreationDate", "N/A"))[:60],
                    "Date modif": str(pdf.metadata.get("ModDate", "N/A"))[:60],
                }
            for page in pdf.pages:
                texte += page.extract_text() or ""

        return PDFAnalysis(
            texte=texte,
            metadata=metadata_dict,
            raw_bytes=pdf_bytes,
            hash_sha256=hash_sha256,
            error=None,
        )
    except Exception as e:
        logger.error(f"Erreur extraction PDF: {e}")
        try:
            fichier_pdf.seek(0)
            pdf_bytes = fichier_pdf.read()
        except Exception:
            pdf_bytes = b""
        return PDFAnalysis(
            texte="",
            metadata={},
            raw_bytes=pdf_bytes,
            hash_sha256=hashlib.sha256(pdf_bytes).hexdigest() if pdf_bytes else "",
            error=f"Lecture partielle : {str(e)[:60]}",
        )


# ============== ANALYSE MATHÉMATIQUE ==============

def _to_float(raw: str) -> float:
    """Convertit '1 234,56' ou '1.234,56' ou '1234.56' en float."""
    s = raw.strip().replace(" ", "").replace(" ", "").replace("\xa0", "")
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def construire_math_result(texte: str) -> Tuple[float, float]:
    """Extrait le Net imposable mensuel et le Cumul imposable du texte.
    On cible le NET IMPOSABLE (et non le net à payer), car c'est la base
    qui doit être cohérente avec le cumul imposable."""
    net_imp = 0.0
    cumul = 0.0

    patterns_net = [
        r"net\s+imposable[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
        r"net\s+fiscal[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
        r"montant\s+net\s+imposable[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
    ]
    for p in patterns_net:
        m = re.search(p, texte, re.IGNORECASE)
        if m:
            net_imp = _to_float(m.group(1))
            break

    patterns_cumul = [
        r"cumul\s+(?:net\s+)?imposable[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
        r"net\s+imposable\s+annuel[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
        r"total\s+imposable[^0-9]{0,20}([0-9][0-9\s.,]*[0-9])",
    ]
    for p in patterns_cumul:
        m = re.search(p, texte, re.IGNORECASE)
        if m:
            cumul = _to_float(m.group(1))
            break

    return net_imp, cumul


def analyser_math(net_imposable_mensuel: float, nb_mois: int, cumul_saisi: float) -> MathResult:
    """Cohérence : cumul imposable ≈ net imposable mensuel × nb mois.
    Seuil de tolérance proportionnel (primes/13e mois) : 8 %, min 100 €."""
    calcul_theo = net_imposable_mensuel * nb_mois
    ecart = abs(cumul_saisi - calcul_theo)
    seuil = max(100.0, calcul_theo * 0.08)
    fraude = calcul_theo > 0 and cumul_saisi > 0 and ecart > seuil

    return MathResult(
        est_scan=False,
        ecart=ecart,
        calcul_theorique=calcul_theo,
        net_imposable_mensuel=net_imposable_mensuel,
        mois_cumules=nb_mois,
        cumul_imposable=cumul_saisi,
        fraude_math=fraude,
    )


# ============== ANALYSE FORENSIQUE (RÉELLE) ==============

# Outils d'édition graphique = vrais signaux. On EXCLUT les bibliothèques PDF
# légitimes pour limiter les faux positifs.
OUTILS_EDITION = ["photoshop", "gimp", "canva", "affinity", "indesign", "illustrator",
                  "inkscape", "paint", "pixelmator"]
PRODUCTEURS_LEGITIMES = ["adobe pdf library", "itext", "pdfkit", "tcpdf", "fpdf",
                         "reportlab", "microsoft", "libreoffice", "openoffice",
                         "cegid", "sage", "quadratus", "silae", "pole emploi",
                         "dgfip", "impots", "msword", "wkhtmltopdf"]


def analyser_forensic(analysis: PDFAnalysis) -> ForensicResult:
    """Analyse structurelle réelle du PDF via pikepdf + scan binaire."""
    raw = analysis.raw_bytes or b""
    metadata = analysis.metadata

    # --- 1. Mises à jour incrémentales / xref multiples (PDF remanié) ---
    # Une signature électronique (/ByteRange) ajoute légitimement UNE sauvegarde
    # incrémentielle par signature (le contenu déjà signé n'est pas réécrit).
    # On ne flague comme anormales que les mises à jour non expliquées par une signature,
    # pour éviter de pénaliser les documents officiels signés numériquement.
    nb_eof = len(re.findall(rb"%%EOF", raw))
    incremental_updates = max(nb_eof, 1)
    nb_signatures = len(re.findall(rb"/ByteRange", raw))
    signature_detectee = nb_signatures > 0
    updates_au_dela_original = incremental_updates - 1
    updates_non_expliquees = max(updates_au_dela_original - nb_signatures, 0)
    xref_anormal = updates_non_expliquees > 0

    # --- 2. Outils d'édition dans les métadonnées (hors libs PDF légitimes) ---
    logiciels = []
    for key in ("Créateur", "Producteur", "Auteur"):
        val = str(metadata.get(key, "")).lower()
        if not val or val == "n/a":
            continue
        if any(legit in val for legit in PRODUCTEURS_LEGITIMES):
            continue
        for outil in OUTILS_EDITION:
            if outil in val and outil.capitalize() not in logiciels:
                logiciels.append(outil.capitalize())

    # --- 3. Date de modification postérieure à la création ---
    # Signal faible et peu fiable en soi (resignature, réexport, conversion changent
    # légitimement ModDate) : reste affiché à titre informatif mais pèse peu dans le score,
    # et n'est pas compté du tout si le document est signé électroniquement.
    date_modifiee = False
    creation = str(metadata.get("Date création", "")).strip()
    modif = str(metadata.get("Date modif", "")).strip()
    if creation not in ("", "N/A") and modif not in ("", "N/A") and creation != modif:
        date_modifiee = True

    # --- 4 à 7. Structure objet via pikepdf ---
    javascript_suspect = False
    fichiers_incorpores = False
    annotations_suspectes = False
    fonts: List[str] = []

    try:
        with pikepdf.open(BytesIO(raw)) as pdf:
            root = pdf.Root

            if "/OpenAction" in root:
                javascript_suspect = True
            if "/AA" in root:
                javascript_suspect = True
            names = root.get("/Names", None)
            if names is not None and "/JavaScript" in names:
                javascript_suspect = True
            if names is not None and "/EmbeddedFiles" in names:
                fichiers_incorpores = True

            for page in pdf.pages:
                annots = page.get("/Annots", None)
                if annots is not None:
                    for a in annots:
                        subtype = str(a.get("/Subtype", ""))
                        # /Stamp exclu : cachets et tampons de certification légitimes
                        # (ex. "certifié conforme") l'utilisent couramment — trop de faux positifs.
                        if subtype in ("/FreeText", "/Redact"):
                            annotations_suspectes = True

                res = page.get("/Resources", None)
                if res is not None:
                    fdict = res.get("/Font", None)
                    if fdict is not None:
                        for f in fdict.values():
                            base = f.get("/BaseFont", None)
                            if base is not None:
                                name = str(base).lstrip("/")
                                name = re.sub(r"^[A-Z]{6}\+", "", name)
                                if name and name not in fonts:
                                    fonts.append(name)

        if not javascript_suspect and (b"/JavaScript" in raw or b"/JS" in raw):
            javascript_suspect = True
        if not fichiers_incorpores and b"/EmbeddedFile" in raw:
            fichiers_incorpores = True

    except Exception as e:
        logger.warning(f"pikepdf : analyse partielle ({e}). Repli scan binaire.")
        if b"/JavaScript" in raw or b"/JS" in raw:
            javascript_suspect = True
        if b"/EmbeddedFile" in raw:
            fichiers_incorpores = True

    # --- Score forensique pondéré ---
    score = 0
    if xref_anormal:
        score += 30
    if logiciels:
        score += 25
    if date_modifiee and not signature_detectee:
        score += 5
    if javascript_suspect:
        score += 20
    if fichiers_incorpores:
        score += 15
    if annotations_suspectes:
        score += 20
    score = min(score, 100)

    return ForensicResult(
        hash_sha256=analysis.hash_sha256,
        incremental_updates=incremental_updates,
        xref_anormal=xref_anormal,
        fraude_meta=len(logiciels) > 0,
        signature_detectee=signature_detectee,
        logiciels_detectes=logiciels,
        date_modifiee=date_modifiee,
        javascript_suspect=javascript_suspect,
        fichiers_incorpores=fichiers_incorpores,
        annotations_suspectes=annotations_suspectes,
        fonts_detectees=fonts,
        score_risque_forensic=score,
    )


def calculer_verdict(math: MathResult, forensic: ForensicResult) -> Verdict:
    """Verdict global. La forensique pèse plus que le calcul (moins de faux positifs)."""
    score_math = 45 if math.fraude_math else 0
    score_forensic = forensic.score_risque_forensic
    score_global = int(0.6 * score_forensic + 0.4 * score_math)
    score_global = min(score_global, 100)

    if score_global >= 70:
        statut = "🔴 ANOMALIES MAJEURES sur le document — Vérification humaine obligatoire"
    elif score_global >= 40:
        statut = "🟠 ANOMALIES MODÉRÉES sur le document — Vérification humaine recommandée"
    else:
        statut = "🟢 AUCUNE ANOMALIE TECHNIQUE détectée sur le document"

    return Verdict(
        score_risque=score_global,
        statut=statut,
        date_analyse=datetime.now().strftime("%d/%m/%Y à %H:%M"),
    )


# ============== ANALYSE CROISÉE (formules Sécurisé / Dossier Complet) ==============

def analyser_dossier_croise(docs: List[DocumentAnalyse]) -> CrossDocResult:
    """Cohérence entre plusieurs documents d'un même dossier.
    Ne signale que des écarts fiables (peu de faux positifs) : fichiers identiques
    déposés deux fois, et variations fortes et inexpliquées entre plusieurs fiches
    de paie du même dossier."""
    cross = CrossDocResult(nb_documents=len(docs))

    par_hash: dict = {}
    for d in docs:
        par_hash.setdefault(d.analysis.hash_sha256, []).append(d.nom_fichier)
    for noms in par_hash.values():
        if len(noms) > 1:
            cross.doublons_detectes = True
            cross.fichiers_dupliques.extend(noms)

    fiches = [d for d in docs
              if d.type_document == "Fiche de paie" and d.math.net_imposable_mensuel > 0]
    for a, b in zip(fiches, fiches[1:]):
        base = max(a.math.net_imposable_mensuel, b.math.net_imposable_mensuel)
        ecart_pct = abs(a.math.net_imposable_mensuel - b.math.net_imposable_mensuel) / base
        if ecart_pct > 0.30:
            cross.incoherence_financiere = True
            cross.ecarts_fiches_paie.append(
                f"« {a.nom_fichier} » ({a.math.net_imposable_mensuel:.2f} €) et "
                f"« {b.nom_fichier} » ({b.math.net_imposable_mensuel:.2f} €) : écart de "
                f"{ecart_pct * 100:.0f} % du net imposable mensuel — à faire expliquer par le candidat."
            )

    return cross


def calculer_verdict_dossier(docs: List[DocumentAnalyse], cross: CrossDocResult) -> Verdict:
    """Verdict global d'un dossier à plusieurs documents.
    Le score forensique retenu est le MAX (et non la moyenne) des documents : un seul
    document falsifié ne doit pas être dilué par des pièces saines. Les anomalies
    croisées (doublons, écarts entre fiches de paie) s'ajoutent par-dessus."""
    if not docs:
        return Verdict(score_risque=0,
                        statut="🟢 AUCUNE ANOMALIE TECHNIQUE détectée sur le dossier",
                        date_analyse=datetime.now().strftime("%d/%m/%Y à %H:%M"))

    score_forensic_max = max(d.forensic.score_risque_forensic for d in docs)
    fraude_math = any(d.math.fraude_math for d in docs)
    score_math = 45 if fraude_math else 0
    score_global = int(0.6 * score_forensic_max + 0.4 * score_math)
    if cross.doublons_detectes:
        score_global += 20
    if cross.incoherence_financiere:
        score_global += 10
    score_global = min(score_global, 100)

    if score_global >= 70:
        statut = "🔴 ANOMALIES MAJEURES sur le dossier — Vérification humaine obligatoire"
    elif score_global >= 40:
        statut = "🟠 ANOMALIES MODÉRÉES sur le dossier — Vérification humaine recommandée"
    else:
        statut = "🟢 AUCUNE ANOMALIE TECHNIQUE détectée sur le dossier"

    return Verdict(
        score_risque=score_global,
        statut=statut,
        date_analyse=datetime.now().strftime("%d/%m/%Y à %H:%M"),
    )


# ============== RAPPORT PDF (mise en page professionnelle) ==============

# Palette de marque
INK = HexColor('#0F172A')        # navy
INK2 = HexColor('#1E293B')
AMBER = HexColor('#F59E0B')
SLATE = HexColor('#475569')
SLATE_LT = HexColor('#94A3B8')
LINE = HexColor('#E2E8F0')
ROW_ALT = HexColor('#F8FAFC')
GREEN = HexColor('#16A34A')
RED = HexColor('#DC2626')
ORANGE = HexColor('#D97706')


def _status_visuals(score: int):
    """(couleur, teinte de fond, libellé court, libellé long)."""
    if score >= 70:
        return RED, HexColor('#FEF2F2'), "RISQUE ÉLEVÉ", "Anomalies majeures — vérification humaine obligatoire"
    if score >= 40:
        return ORANGE, HexColor('#FFF7ED'), "VIGILANCE", "Anomalies modérées — vérification humaine recommandée"
    return GREEN, HexColor('#F0FDF4'), "CONFORME", "Aucune anomalie technique détectée"


class NumberedCanvas(rl_canvas.Canvas):
    """En-tête de marque + pied de page avec « Page X sur Y » sur chaque page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_states = []

    def showPage(self):
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_states)
        for state in self._saved_states:
            self.__dict__.update(state)
            self._draw_furniture(total)
            super().showPage()
        super().save()

    def _draw_furniture(self, total):
        w, h = A4
        # --- En-tête ---
        self.setFillColor(INK)
        self.rect(0, h - 46, w, 46, fill=1, stroke=0)
        self.setFillColor(AMBER)
        self.rect(0, h - 49, w, 3, fill=1, stroke=0)
        # Bouclier stylisé
        self.setFillColor(AMBER)
        self.setStrokeColor(AMBER)
        self.setLineWidth(1.4)
        sx, sy = 42, h - 30
        self.setFont('Helvetica-Bold', 17)
        self.setFillColor(colors.white)
        self.drawString(40, h - 30, "BAIL")
        bail_w = self.stringWidth("BAIL", 'Helvetica-Bold', 17)
        self.setFillColor(AMBER)
        self.drawString(40 + bail_w, h - 30, "SAFE")
        self.setFont('Helvetica', 7.5)
        self.setFillColor(HexColor('#CBD5E1'))
        self.drawString(42, h - 41, "AUDIT ANTI-FRAUDE LOCATIF · ANALYSE FORENSIQUE")
        self.setFont('Helvetica', 7.5)
        self.setFillColor(HexColor('#CBD5E1'))
        self.drawRightString(w - 40, h - 30, "RAPPORT D'AUDIT")
        self.drawRightString(w - 40, h - 41, "CONFIDENTIEL")
        # --- Pied de page ---
        self.setStrokeColor(LINE)
        self.setLineWidth(0.6)
        self.line(40, 34, w - 40, 34)
        self.setFont('Helvetica', 7.5)
        self.setFillColor(SLATE_LT)
        self.drawString(40, 22, "BailSafe · bunetnolan@gmail.com · Sainte-Rose, Guadeloupe")
        self.drawCentredString(w / 2, 22, "Document confidentiel — destiné au bailleur")
        self.drawRightString(w - 40, 22, f"Page {self._pageNumber} sur {total}")


class ScoreGauge(Flowable):
    """Bandeau verdict : pastille de statut, score géant et jauge horizontale."""

    def __init__(self, score, width, color, tint, label_court, label_long):
        super().__init__()
        self.score = max(0, min(int(score), 100))
        self.width = width
        self.height = 96
        self.color = color
        self.tint = tint
        self.label_court = label_court
        self.label_long = label_long

    def wrap(self, *args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        w, h = self.width, self.height
        # Fond teinté + cadre
        c.setFillColor(self.tint)
        c.setStrokeColor(self.color)
        c.setLineWidth(1.2)
        c.roundRect(0, 0, w, h, 10, fill=1, stroke=1)
        # Barre d'accent gauche
        c.setFillColor(self.color)
        c.roundRect(0, 0, 7, h, 3, fill=1, stroke=0)
        # Pastille de statut
        pad = 22
        c.setFillColor(self.color)
        c.roundRect(pad, h - 36, 132, 20, 10, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont('Helvetica-Bold', 9.5)
        c.drawCentredString(pad + 66, h - 30, self.label_court)
        # Libellé long
        c.setFillColor(INK2)
        c.setFont('Helvetica-Bold', 11)
        c.drawString(pad, h - 56, "Indice d'anomalie documentaire")
        c.setFillColor(SLATE)
        c.setFont('Helvetica', 8.5)
        c.drawString(pad, h - 69, self.label_long)
        # Score géant (droite)
        c.setFillColor(self.color)
        c.setFont('Helvetica-Bold', 40)
        c.drawRightString(w - 24, h - 46, str(self.score))
        c.setFillColor(SLATE_LT)
        c.setFont('Helvetica', 11)
        c.drawRightString(w - 24, h - 60, "/ 100")
        # Jauge
        gx, gy, gw, gh = pad, 16, w - pad - 24, 9
        c.setFillColor(HexColor('#E5E7EB'))
        c.roundRect(gx, gy, gw, gh, 4.5, fill=1, stroke=0)
        c.setFillColor(self.color)
        fill_w = max(gh, gw * self.score / 100.0)
        c.roundRect(gx, gy, fill_w, gh, 4.5, fill=1, stroke=0)
        # Graduations 40 / 70
        c.setStrokeColor(colors.white)
        c.setLineWidth(1)
        for seuil in (40, 70):
            mx = gx + gw * seuil / 100.0
            c.line(mx, gy, mx, gy + gh)


def _section_title(text, styles):
    """Titre de section avec filet ambre."""
    return Paragraph(
        f'<font color="#0F172A"><b>{text}</b></font>',
        ParagraphStyle('Sec', parent=styles['Normal'], fontSize=12.5,
                       fontName='Helvetica-Bold', textColor=INK, spaceBefore=4, spaceAfter=2))


_SIGNAL_LABEL_STYLE = ParagraphStyle('SigLabel', fontName='Helvetica-Bold', fontSize=8.8,
                                     textColor=HexColor('#1E293B'), leading=11.5)
_SIGNAL_DETAIL_STYLE = ParagraphStyle('SigDetail', fontName='Helvetica', fontSize=8.8,
                                      textColor=HexColor('#475569'), leading=11.5)


def _signal_table(rows, col_widths):
    """rows = list of (label, detail, flag_bool|None, value_text).
    flag None = neutre (info). True = alerte. False = OK.
    Label et détail sont enveloppés dans des Paragraph pour se replier proprement à la
    ligne (un texte trop long dépasserait sinon la largeur de colonne et chevaucherait
    la pastille de statut)."""
    data = []
    styles_extra = []
    for i, (label, detail, flag, value) in enumerate(rows):
        if flag is None:
            badge, bcolor, btext = ROW_ALT, SLATE, value
        elif flag:
            badge, bcolor, btext = HexColor('#FEE2E2'), RED, value or "DÉTECTÉ"
        else:
            badge, bcolor, btext = HexColor('#DCFCE7'), GREEN, value or "OK"
        data.append([Paragraph(label, _SIGNAL_LABEL_STYLE),
                    Paragraph(detail, _SIGNAL_DETAIL_STYLE), btext])
        r = len(data) - 1
        styles_extra.append(('BACKGROUND', (2, r), (2, r), badge))
        styles_extra.append(('TEXTCOLOR', (2, r), (2, r), bcolor))
        styles_extra.append(('FONTNAME', (2, r), (2, r), 'Helvetica-Bold'))
        if r % 2 == 1:
            styles_extra.append(('BACKGROUND', (0, r), (1, r), ROW_ALT))
    t = Table(data, colWidths=col_widths)
    base = [
        ('TEXTCOLOR', (0, 0), (0, -1), INK2),
        ('TEXTCOLOR', (1, 0), (1, -1), SLATE),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8.8),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8), ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12), ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, LINE),
        ('BOX', (0, 0), (-1, -1), 0.8, LINE),
    ]
    t.setStyle(TableStyle(base + styles_extra))
    return t


def _append_forensic_financial_sections(story, styles, usable, forensic: ForensicResult,
                                         math: MathResult, titre_suffixe: str = "") -> None:
    """Ajoute au récit ReportLab le tableau forensique puis, si pertinent, le tableau de
    cohérence financière d'UN document. Factorisé pour être réutilisé tel quel dans le
    rapport mono-document et dans chaque section du rapport de dossier multi-documents."""
    date_modifiee_comptee = forensic.date_modifiee and not forensic.signature_detectee

    story.append(_section_title(f"Analyse forensique du fichier{titre_suffixe}", styles))
    story.append(Spacer(1, 6))
    xref_detail = (f"{forensic.incremental_updates} sauvegarde(s) — "
                  + ("document remanié après émission" if forensic.xref_anormal else "structure d'origine"))
    if forensic.signature_detectee and not forensic.xref_anormal:
        xref_detail += " (cohérent avec signature électronique)"
    forensic_rows = [
        ("Structure du fichier (xref)", xref_detail,
         forensic.xref_anormal, "REMANIÉ" if forensic.xref_anormal else "INTÈGRE"),
        ("Signature électronique",
         "Document signé numériquement" if forensic.signature_detectee else "Aucune signature détectée",
         None, "OUI" if forensic.signature_detectee else "NON"),
        ("Outils d'édition graphique",
         ", ".join(forensic.logiciels_detectes) or "Aucun outil de retouche détecté",
         forensic.fraude_meta, None),
        ("Date de modification",
         ("Modifié après création (signal faible, non déterminant ici)"
          if date_modifiee_comptee
          else ("Modifié après création — cohérent avec la signature" if forensic.date_modifiee
                else "Cohérente avec la création")),
         date_modifiee_comptee, None),
        ("JavaScript embarqué",
         "Code exécutable présent" if forensic.javascript_suspect else "Aucun code détecté",
         forensic.javascript_suspect, None),
        ("Fichiers incorporés",
         "Pièces jointes masquées" if forensic.fichiers_incorpores else "Aucun fichier incorporé",
         forensic.fichiers_incorpores, None),
        ("Annotations superposées",
         "Texte/tampon ajouté par-dessus" if forensic.annotations_suspectes else "Aucune surcouche",
         forensic.annotations_suspectes, None),
        ("Polices détectées", f"{len(forensic.fonts_detectees)} police(s) dans le document",
         None, str(len(forensic.fonts_detectees))),
    ]
    story.append(_signal_table(forensic_rows, [56 * mm, 78 * mm, 26 * mm]))
    story.append(Spacer(1, 16))

    if not math.est_scan and math.calcul_theorique > 0:
        story.append(_section_title(f"Cohérence financière{titre_suffixe}", styles))
        story.append(Spacer(1, 6))
        seuil = max(100.0, math.calcul_theorique * 0.08)
        fin_rows = [
            ("Net imposable mensuel", f"{math.net_imposable_mensuel:,.2f} €".replace(",", " "),
             None, ""),
            ("Mois cumulés", f"{math.mois_cumules} mois", None, ""),
            ("Cumul théorique attendu", f"{math.calcul_theorique:,.2f} €".replace(",", " "),
             None, ""),
            ("Cumul imposable déclaré", f"{math.cumul_imposable:,.2f} €".replace(",", " "),
             None, ""),
            ("Écart vs seuil de tolérance",
             f"{math.ecart:,.2f} € (seuil {seuil:,.0f} €)".replace(",", " "),
             math.fraude_math, "ANOMALIE" if math.fraude_math else "COHÉRENT"),
        ]
        story.append(_signal_table(fin_rows, [56 * mm, 78 * mm, 26 * mm]))
        story.append(Spacer(1, 16))


def build_report_pdf(verdict: Verdict, forensic: ForensicResult, math: MathResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=40, rightMargin=40, topMargin=70, bottomMargin=46,
        title="Rapport d'audit BailSafe", author="BailSafe",
    )
    usable = doc.width - 12  # largeur utile (cadre ReportLab : 6 pt de padding par côté)
    styles = getSampleStyleSheet()
    normal = ParagraphStyle('N', parent=styles['Normal'], fontSize=9.2,
                            textColor=SLATE, leading=14, spaceAfter=5)
    small = ParagraphStyle('S', parent=styles['Normal'], fontSize=8,
                           textColor=SLATE_LT, leading=11)
    meta_lbl = ParagraphStyle('ML', parent=styles['Normal'], fontSize=7.5,
                              textColor=SLATE_LT, fontName='Helvetica-Bold', leading=10)
    meta_val = ParagraphStyle('MV', parent=styles['Normal'], fontSize=9,
                              textColor=INK2, fontName='Helvetica-Bold', leading=12)

    color, tint, label_court, label_long = _status_visuals(verdict.score_risque)
    ref = f"BS-{datetime.now().strftime('%Y%m%d')}-{forensic.hash_sha256[:6].upper()}"

    story = []

    # --- Bandeau méta (référence / date / empreinte) ---
    meta = Table([[
        [Paragraph("RÉFÉRENCE", meta_lbl), Paragraph(ref, meta_val)],
        [Paragraph("DATE D'ANALYSE", meta_lbl), Paragraph(verdict.date_analyse, meta_val)],
        [Paragraph("EMPREINTE SHA-256", meta_lbl),
         Paragraph(f"{forensic.hash_sha256[:20]}…", meta_val)],
    ]], colWidths=[usable / 3.0] * 3)
    meta.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (0, 0), 0),
        ('LINEAFTER', (0, 0), (0, 0), 0.6, LINE),
        ('LINEAFTER', (1, 0), (1, 0), 0.6, LINE),
        ('LEFTPADDING', (1, 0), (-1, 0), 16),
        ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta)
    story.append(Spacer(1, 14))

    # --- Bandeau verdict (jauge) ---
    story.append(ScoreGauge(verdict.score_risque, usable, color, tint, label_court, label_long))
    story.append(Spacer(1, 18))

    # --- Synthèse ---
    date_modifiee_comptee = forensic.date_modifiee and not forensic.signature_detectee
    nb_signaux = sum([forensic.xref_anormal, forensic.fraude_meta, date_modifiee_comptee,
                      forensic.javascript_suspect, forensic.fichiers_incorpores,
                      forensic.annotations_suspectes, math.fraude_math])
    synth = (f"L'analyse technique du document a relevé <b>{nb_signaux} signal(aux) d'alerte</b> "
             f"sur {7} contrôles effectués (structure du fichier, métadonnées, cohérence "
             f"financière). Ce rapport détaille chaque contrôle ci-dessous. Il porte exclusivement "
             f"sur l'intégrité technique du document, non sur la personne du candidat.")
    story.append(_section_title("Synthèse", styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph(synth, normal))
    story.append(Spacer(1, 14))

    # --- Analyse forensique + cohérence financière ---
    _append_forensic_financial_sections(story, styles, usable, forensic, math)

    # --- Recommandations ---
    story.append(_section_title("Recommandations", styles))
    story.append(Spacer(1, 4))
    if verdict.score_risque >= 70:
        recs = [
            "<b>Suspendre la décision</b> et demander l'original du document au candidat.",
            "Procéder à une <b>vérification humaine complémentaire</b> (employeur, organisme émetteur).",
            "La <b>décision finale</b> d'accepter ou refuser le dossier appartient au bailleur.",
        ]
    elif verdict.score_risque >= 40:
        recs = [
            "<b>Signaler les anomalies</b> détectées au bailleur.",
            "<b>Vérification humaine rapide</b> recommandée avant signature.",
            "<b>Demander une explication écrite</b> au candidat.",
        ]
    else:
        recs = [
            "Aucune anomalie technique — le dossier peut être <b>instruit normalement</b>.",
            "Ce rapport peut servir de <b>justificatif de diligence</b>.",
        ]
    rec_style = ParagraphStyle('Rec', parent=normal, leftIndent=14, firstLineIndent=-12,
                               bulletIndent=0, spaceAfter=6)
    for r in recs:
        story.append(Paragraph(f'<font color="#F59E0B"><b>›</b></font>&nbsp;&nbsp;{r}', rec_style))
    story.append(Spacer(1, 14))

    # --- Avertissement légal (encadré) ---
    purge_date = (datetime.now() + timedelta(days=30)).strftime("%d/%m/%Y")
    legal_text = ("Ce rapport est une analyse technique automatisée fournie à titre consultatif. "
                  "Il porte sur l'intégrité et la structure du document, non sur la personne. Il ne "
                  "constitue pas une garantie juridique et ne vaut pas décision : la décision "
                  "d'accepter ou de refuser un dossier appartient exclusivement au bailleur (aucune "
                  "décision automatisée au sens de l'article 22 du RGPD). BailSafe ne peut être tenu "
                  "responsable des décisions prises sur la base de ce rapport. Une falsification suivie "
                  "d'une impression puis d'un nouveau scan peut échapper à l'analyse. Conformément à "
                  f"l'article 5.1.e du RGPD, ce rapport et le document source doivent être supprimés "
                  f"par le bailleur (y compris de sa messagerie) au plus tard le <b>{purge_date}</b> "
                  f"(30 jours après l'analyse).")
    legal_box = Table([[Paragraph(
        f'<font color="#475569"><b>AVERTISSEMENT LÉGAL — </b></font>'
        f'<font color="#64748B">{legal_text}</font>',
        ParagraphStyle('L', parent=styles['Normal'], fontSize=7.6, leading=11,
                       textColor=SLATE))]], colWidths=[usable])
    legal_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.6, LINE),
        ('LINEBEFORE', (0, 0), (0, -1), 2.5, AMBER),
        ('TOPPADDING', (0, 0), (-1, -1), 10), ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 14), ('RIGHTPADDING', (0, 0), (-1, -1), 14),
    ]))
    story.append(legal_box)

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def build_dossier_report_pdf(verdict: Verdict, docs: List[DocumentAnalyse],
                              cross: CrossDocResult) -> bytes:
    """Rapport combiné pour un dossier de 2 à 4 documents (formules Sécurisé /
    Dossier Complet) : bandeau verdict global, section de cohérence croisée, puis
    le détail forensique + financier de chaque document."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=40, rightMargin=40, topMargin=70, bottomMargin=46,
        title="Rapport d'audit BailSafe — Dossier", author="BailSafe",
    )
    usable = doc.width - 12
    styles = getSampleStyleSheet()
    normal = ParagraphStyle('N', parent=styles['Normal'], fontSize=9.2,
                            textColor=SLATE, leading=14, spaceAfter=5)
    meta_lbl = ParagraphStyle('ML', parent=styles['Normal'], fontSize=7.5,
                              textColor=SLATE_LT, fontName='Helvetica-Bold', leading=10)
    meta_val = ParagraphStyle('MV', parent=styles['Normal'], fontSize=9,
                              textColor=INK2, fontName='Helvetica-Bold', leading=12)

    color, tint, label_court, label_long = _status_visuals(verdict.score_risque)
    empreinte_dossier = hashlib.sha256(
        "".join(d.analysis.hash_sha256 for d in docs).encode()
    ).hexdigest()
    ref = f"BS-{datetime.now().strftime('%Y%m%d')}-{empreinte_dossier[:6].upper()}"

    story = []

    # --- Bandeau méta ---
    meta = Table([[
        [Paragraph("RÉFÉRENCE DOSSIER", meta_lbl), Paragraph(ref, meta_val)],
        [Paragraph("DATE D'ANALYSE", meta_lbl), Paragraph(verdict.date_analyse, meta_val)],
        [Paragraph("DOCUMENTS ANALYSÉS", meta_lbl), Paragraph(str(len(docs)), meta_val)],
    ]], colWidths=[usable / 3.0] * 3)
    meta.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (0, 0), 0),
        ('LINEAFTER', (0, 0), (0, 0), 0.6, LINE),
        ('LINEAFTER', (1, 0), (1, 0), 0.6, LINE),
        ('LEFTPADDING', (1, 0), (-1, 0), 16),
        ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta)
    story.append(Spacer(1, 14))

    # --- Bandeau verdict global (jauge) ---
    story.append(ScoreGauge(verdict.score_risque, usable, color, tint, label_court, label_long))
    story.append(Spacer(1, 18))

    # --- Synthèse dossier ---
    noms = ", ".join(f"« {d.nom_fichier} » ({d.type_document})" for d in docs)
    synth = (f"Ce dossier comprend <b>{len(docs)} document(s)</b> : {noms}. Le score global "
             f"retient le signal le plus fort parmi les documents (une seule pièce anormale "
             f"suffit à alerter, même si les autres sont conformes) et intègre la cohérence "
             f"entre les pièces du dossier. Le détail de chaque document suit ci-dessous.")
    story.append(_section_title("Synthèse du dossier", styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph(synth, normal))
    story.append(Spacer(1, 14))

    # --- Cohérence entre les documents ---
    story.append(_section_title("Cohérence entre les documents du dossier", styles))
    story.append(Spacer(1, 6))
    cross_rows = [
        ("Documents identiques déposés en double",
         ", ".join(cross.fichiers_dupliques) if cross.doublons_detectes
         else "Aucun fichier dupliqué détecté",
         cross.doublons_detectes, "DÉTECTÉ" if cross.doublons_detectes else "OK"),
        ("Cohérence entre fiches de paie",
         " | ".join(cross.ecarts_fiches_paie) if cross.ecarts_fiches_paie
         else "Aucun écart significatif entre les fiches de paie du dossier",
         cross.incoherence_financiere, "À VÉRIFIER" if cross.incoherence_financiere else "OK"),
    ]
    story.append(_signal_table(cross_rows, [56 * mm, 78 * mm, 26 * mm]))
    story.append(Spacer(1, 18))

    # --- Détail par document ---
    for i, d in enumerate(docs, start=1):
        story.append(_section_title(f"Document {i}/{len(docs)} — {d.nom_fichier} "
                                     f"({d.type_document})", styles))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Empreinte SHA-256 : <font face='Courier'>{d.analysis.hash_sha256[:24]}…</font> · "
            f"Score forensique individuel : <b>{d.forensic.score_risque_forensic}/100</b>",
            normal))
        story.append(Spacer(1, 6))
        _append_forensic_financial_sections(story, styles, usable, d.forensic, d.math,
                                             titre_suffixe=f" — Document {i}")
        story.append(Spacer(1, 4))

    # --- Recommandations ---
    story.append(_section_title("Recommandations", styles))
    story.append(Spacer(1, 4))
    if verdict.score_risque >= 70:
        recs = [
            "<b>Suspendre la décision</b> et demander les originaux au candidat.",
            "Procéder à une <b>vérification humaine complémentaire</b> (employeur, organisme émetteur).",
            "La <b>décision finale</b> d'accepter ou refuser le dossier appartient au bailleur.",
        ]
    elif verdict.score_risque >= 40:
        recs = [
            "<b>Signaler les anomalies</b> détectées au bailleur.",
            "<b>Vérification humaine rapide</b> recommandée avant signature.",
            "<b>Demander une explication écrite</b> au candidat.",
        ]
    else:
        recs = [
            "Aucune anomalie technique — le dossier peut être <b>instruit normalement</b>.",
            "Ce rapport peut servir de <b>justificatif de diligence</b>.",
        ]
    rec_style = ParagraphStyle('Rec', parent=normal, leftIndent=14, firstLineIndent=-12,
                               bulletIndent=0, spaceAfter=6)
    for r in recs:
        story.append(Paragraph(f'<font color="#F59E0B"><b>›</b></font>&nbsp;&nbsp;{r}', rec_style))
    story.append(Spacer(1, 14))

    # --- Avertissement légal (encadré) ---
    purge_date = (datetime.now() + timedelta(days=30)).strftime("%d/%m/%Y")
    legal_text = ("Ce rapport est une analyse technique automatisée fournie à titre consultatif. "
                  "Il porte sur l'intégrité et la structure des documents, non sur la personne. Il ne "
                  "constitue pas une garantie juridique et ne vaut pas décision : la décision "
                  "d'accepter ou de refuser un dossier appartient exclusivement au bailleur (aucune "
                  "décision automatisée au sens de l'article 22 du RGPD). BailSafe ne peut être tenu "
                  "responsable des décisions prises sur la base de ce rapport. Une falsification suivie "
                  "d'une impression puis d'un nouveau scan peut échapper à l'analyse. Conformément à "
                  f"l'article 5.1.e du RGPD, ce rapport et les documents sources doivent être supprimés "
                  f"par le bailleur (y compris de sa messagerie) au plus tard le <b>{purge_date}</b> "
                  f"(30 jours après l'analyse).")
    legal_box = Table([[Paragraph(
        f'<font color="#475569"><b>AVERTISSEMENT LÉGAL — </b></font>'
        f'<font color="#64748B">{legal_text}</font>',
        ParagraphStyle('L', parent=styles['Normal'], fontSize=7.6, leading=11,
                       textColor=SLATE))]], colWidths=[usable])
    legal_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.6, LINE),
        ('LINEBEFORE', (0, 0), (0, -1), 2.5, AMBER),
        ('TOPPADDING', (0, 0), (-1, -1), 10), ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 14), ('RIGHTPADDING', (0, 0), (-1, -1), 14),
    ]))
    story.append(legal_box)

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def get_report_filename(statut: str, dossier: bool = False) -> str:
    date = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffixe = "_Dossier" if dossier else ""
    if statut.startswith("🔴"):
        return f"BailSafe_ALERTE{suffixe}_{date}.pdf"
    elif statut.startswith("🟠"):
        return f"BailSafe_ATTENTION{suffixe}_{date}.pdf"
    return f"BailSafe_CONFORME{suffixe}_{date}.pdf"


# ============== EMAIL ==============

def envoyer_rapport(secrets: AppSecrets, email_dest: str, pdf_bytes: bytes, filename: str) -> Tuple[bool, str]:
    if not secrets.email_expediteur or not secrets.mot_de_passe_email:
        return False, "❌ Secrets email non configurés."
    try:
        msg = MIMEMultipart()
        msg['From'] = secrets.email_expediteur
        msg['To'] = email_dest
        msg['Subject'] = "Votre rapport BailSafe — Audit anti-fraude"
        purge_date = (datetime.now() + timedelta(days=30)).strftime("%d/%m/%Y")
        body = ("Bonjour,\n\n"
                "Veuillez trouver ci-joint votre rapport d'audit documentaire BailSafe.\n\n"
                "Ce rapport est confidentiel et destiné au bailleur uniquement.\n\n"
                "Conformément à notre politique de conservation des données (RGPD art. 5.1.e), "
                f"merci de supprimer cet email et sa pièce jointe au plus tard le {purge_date} "
                "(30 jours après l'analyse).\n\n"
                "Cordialement,\nNolan — BailSafe")
        msg.attach(MIMEText(body, 'plain'))

        part = MIMEBase('application', 'octet-stream')
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={filename}')
        msg.attach(part)

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(secrets.email_expediteur, secrets.mot_de_passe_email)
            server.send_message(msg)

        logger.info(f"Email envoyé à {email_dest}")
        return True, f"✅ Rapport envoyé à {email_dest}"
    except Exception as e:
        logger.error(f"Erreur envoi email: {e}")
        return False, f"❌ Erreur envoi: {str(e)[:80]}"


def is_valid_email(email: str) -> bool:
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None


def get_secrets() -> AppSecrets:
    email = os.getenv("EMAIL_EXPEDITEUR")
    mdp = os.getenv("MOT_DE_PASSE_EMAIL")
    if not email or not mdp:
        try:
            email = st.secrets["EMAIL_EXPEDITEUR"]
            mdp = st.secrets["MOT_DE_PASSE_EMAIL"]
        except Exception:
            st.warning("⚠️ Secrets email non configurés — l'envoi par email sera indisponible.")
            return AppSecrets(email_expediteur="", mot_de_passe_email="")
    return AppSecrets(email_expediteur=email, mot_de_passe_email=mdp)


def check_password() -> bool:
    """Porte d'accès. SÉCURITÉ : si aucun mot de passe n'est défini, l'accès est REFUSÉ.
    Définir EXPERT_PASSWORD (variable d'env ou st.secrets) pour ouvrir l'interface."""
    expected = os.getenv("EXPERT_PASSWORD")
    if not expected:
        try:
            expected = st.secrets["EXPERT_PASSWORD"]
        except Exception:
            expected = None

    if not expected:
        st.error(
            "🔒 Accès verrouillé. Aucun mot de passe expert n'est configuré. "
            "Définissez la variable `EXPERT_PASSWORD` (environnement ou secrets) "
            "avant d'exposer cette interface — elle traite des données personnelles sensibles."
        )
        return False

    if st.session_state.get("auth_ok"):
        return True

    pwd = st.text_input("🔒 Mot de passe d'accès expert", type="password")
    if pwd:
        if hmac.compare_digest(pwd, str(expected)):
            st.session_state["auth_ok"] = True
            return True
        st.error("Mot de passe incorrect.")
    return False


# ============== INTERFACE STREAMLIT ==============

def _afficher_coherence_financiere_doc(analysis: PDFAnalysis, key_prefix: str) -> MathResult:
    """Affiche les contrôles de cohérence financière pour UN document et renvoie le résultat.
    Factorisé pour être appelé une fois par document dans un dossier multi-pièces."""
    est_scan = len(analysis.texte.strip()) < 20

    if est_scan:
        st.warning("⚠️ Aucun texte numérique détecté — PDF scanné ou photo. "
                   "Saisissez manuellement les montants.")
        return MathResult(True, 0, 0, 0, 0, 0, False)

    net_auto, cumul_auto = construire_math_result(analysis.texte)
    if net_auto == 0.0:
        st.info("ℹ️ Net imposable non détecté automatiquement — saisie manuelle.")
    if cumul_auto == 0.0:
        st.info("ℹ️ Cumul imposable non détecté automatiquement — saisie manuelle.")

    c1, c2, c3 = st.columns(3)
    with c1:
        net_saisi = st.number_input("Net imposable mensuel (€)", value=net_auto,
                                    min_value=0.0, step=10.0,
                                    help="Ligne « net imposable » de la fiche de paie",
                                    key=f"{key_prefix}_net")
    with c2:
        nb_mois = st.number_input("Mois cumulés", value=1, min_value=1, max_value=36,
                                  key=f"{key_prefix}_mois")
    with c3:
        cumul_saisi = st.number_input("Cumul imposable (€)", value=cumul_auto,
                                      min_value=0.0, step=10.0, key=f"{key_prefix}_cumul")

    math = analyser_math(net_saisi, int(nb_mois), cumul_saisi)
    seuil = max(100.0, math.calcul_theorique * 0.08)

    st.markdown("#### Résultats")
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Cumul théorique", f"{math.calcul_theorique:.2f} €",
                  help=f"{net_saisi} € × {nb_mois} mois")
    with m2:
        st.metric("Écart détecté", f"{math.ecart:.2f} €",
                  delta=f"{math.ecart:.2f} €" if math.fraude_math else "OK",
                  delta_color="inverse" if math.fraude_math else "off")
    with m3:
        st.metric("Seuil d'alerte", f"{seuil:.2f} €", help="8 % du cumul, min 100 €")

    st.divider()
    if math.fraude_math:
        st.error(f"🚨 **ALERTE** — Écart de {math.ecart:.2f} € dépasse le seuil de {seuil:.2f} €")
    elif math.calcul_theorique > 0 and math.cumul_imposable > 0:
        st.success("✅ **CONFORME** — Cohérence mathématique validée")
    else:
        st.info("ℹ️ Saisissez les montants pour évaluer la cohérence.")

    return math


def _afficher_forensique_doc(analysis: PDFAnalysis, forensic: ForensicResult) -> None:
    """Affiche le détail forensique en lecture seule pour UN document."""
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Intégrité du fichier**")
        with st.expander("SHA-256 du fichier (empreinte complète)"):
            st.code(forensic.hash_sha256, language="text")
        xref_status = (f"🔴 Anormal — {forensic.incremental_updates} sauvegardes successives"
                       if forensic.xref_anormal else "🟢 Normal (structure d'origine)")
        if forensic.signature_detectee and not forensic.xref_anormal:
            xref_status += " — cohérent avec signature électronique"
        st.markdown(f"**Sections xref** : {xref_status}")
        st.caption("Plusieurs sections xref = PDF remanié/édité après émission "
                   "(au-delà de ce qu'explique une éventuelle signature électronique).")
        st.markdown(f"**Signature électronique détectée** : "
                    f"{'🟢 Oui' if forensic.signature_detectee else '⚪ Non'}")
        date_modifiee_suffix = (" (signal faible, non compté dans le score : document signé)"
                                if forensic.date_modifiee and forensic.signature_detectee else "")
        st.markdown(f"**Date modifiée après création** : "
                    f"{'🟠 Oui' if forensic.date_modifiee else '🟢 Non'}{date_modifiee_suffix}")

    with col_b:
        st.markdown("**Signaux suspects détectés**")
        items = [
            ("Outils d'édition graphique", forensic.fraude_meta,
             ", ".join(forensic.logiciels_detectes) or "Aucun"),
            ("JavaScript embarqué", forensic.javascript_suspect, ""),
            ("Fichiers incorporés", forensic.fichiers_incorpores, ""),
            ("Annotations superposées", forensic.annotations_suspectes, ""),
        ]
        for label, flag, detail in items:
            icon = "🔴" if flag else "🟢"
            suffix = f" — {detail}" if detail else ""
            st.markdown(f"{icon} {label}{suffix}")
        st.caption(f"Polices détectées : {len(forensic.fonts_detectees)}")

    st.divider()
    st.markdown(f"**Score forensique global : {forensic.score_risque_forensic}/100**")
    st.progress(forensic.score_risque_forensic / 100)
    if forensic.score_risque_forensic == 0:
        st.success("✅ Aucun signal forensique détecté")
    elif forensic.score_risque_forensic < 40:
        st.warning("⚠️ Signaux faibles — à surveiller")
    else:
        st.error("🔴 Signaux forts — document potentiellement falsifié")

    st.divider()
    st.markdown("**Métadonnées du PDF**")
    if analysis.metadata:
        for k, v in analysis.metadata.items():
            st.markdown(f"**{k} :** {v}")
    else:
        st.caption("Aucune métadonnée disponible (peut indiquer un nettoyage des métadonnées).")
    if forensic.fonts_detectees:
        with st.expander(f"Polices utilisées ({len(forensic.fonts_detectees)})"):
            st.write(", ".join(forensic.fonts_detectees))


def afficher_interface_expert() -> None:
    st.markdown("""
    <div style="background:linear-gradient(140deg,#0f172a,#1e3a8a);border:1px solid #f59e0b;
                border-radius:14px;padding:20px 24px;margin-bottom:24px">
        <h2 style="color:#fff;margin:0 0 4px">🕵️ Cockpit d'Analyse Expert</h2>
        <p style="color:#94a3b8;margin:0;font-size:.9rem">
            Forensique PDF réelle (pikepdf) · Cohérence financière · Rapport PDF professionnel
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.caption(
        "🔒 **Traitement RGPD** — Documents analysés en mémoire, non conservés, supprimés en fin de "
        "session. Base légale : intérêt légitime du bailleur + exécution du contrat. Le rapport est un "
        "**avis technique consultatif** : aucune décision automatisée sur les personnes (art. 22 RGPD), "
        "la décision finale revient au bailleur. Informez le candidat que ses pièces sont vérifiées. "
        "Rappel légal : n'auditez que les pièces légalement exigibles (décret n°2015-1437) — "
        "le relevé bancaire ne peut pas être exigé."
    )

    secrets = get_secrets()

    formule_label = st.selectbox("📦 Formule commandée par le client", list(FORMULES.keys()))
    max_docs = FORMULES[formule_label]

    if max_docs == 1:
        fichier_unique = st.file_uploader("📂 Déposez le PDF à auditer", type="pdf")
        fichiers = [fichier_unique] if fichier_unique is not None else []
    else:
        fichiers = st.file_uploader(
            f"📂 Déposez jusqu'à {max_docs} PDF à auditer (formule « {formule_label} »)",
            type="pdf", accept_multiple_files=True,
        ) or []

    if not fichiers:
        st.info("📌 Déposez au moins un fichier PDF pour démarrer l'analyse.")
        return

    if len(fichiers) > max_docs:
        st.error(f"❌ La formule « {formule_label} » autorise {max_docs} document(s) maximum — "
                 f"{len(fichiers)} déposé(s). Retirez-en {len(fichiers) - max_docs} avant de continuer.")
        return

    est_dossier = len(fichiers) > 1

    noms_actuels = tuple(f.name for f in fichiers)
    if st.session_state.get("current_dossier_noms") != noms_actuels:
        st.session_state["current_dossier_noms"] = noms_actuels
        st.session_state["docs_cache"] = {}

    docs_meta = []
    for i, f in enumerate(fichiers):
        cache = st.session_state["docs_cache"].get(f.name)
        if cache is None:
            with st.spinner(f"🔍 Extraction et analyse de « {f.name} »…"):
                analysis = extract_pdf_content(f)
                forensic = analyser_forensic(analysis)
                cache = {"analysis": analysis, "forensic": forensic}
                st.session_state["docs_cache"][f.name] = cache

        label_type = f"Type — « {f.name} »" if est_dossier else "Type de document"
        type_doc = st.selectbox(label_type, TYPES_DOCUMENT, key=f"type_{i}_{f.name}")

        if cache["analysis"].error:
            st.warning(f"⚠️ « {f.name} » : {cache['analysis'].error}")

        docs_meta.append({"nom": f.name, "type": type_doc,
                          "analysis": cache["analysis"], "forensic": cache["forensic"]})

    tab1, tab2, tab3 = st.tabs([
        "📊 Cohérence financière", "🔎 Forensique PDF", "📤 Verdict & Rapport",
    ])

    with tab1:
        st.subheader("Analyse de cohérence mathématique")
        maths = []
        for i, d in enumerate(docs_meta):
            if est_dossier:
                with st.expander(f"« {d['nom']} » — {d['type']}", expanded=(i == 0)):
                    maths.append(_afficher_coherence_financiere_doc(d["analysis"], key_prefix=f"m{i}"))
            else:
                maths.append(_afficher_coherence_financiere_doc(d["analysis"], key_prefix=f"m{i}"))
        st.session_state["maths_results"] = maths

    with tab2:
        st.subheader("Analyse forensique avancée")
        for i, d in enumerate(docs_meta):
            if est_dossier:
                with st.expander(f"« {d['nom']} » — {d['type']}", expanded=(i == 0)):
                    _afficher_forensique_doc(d["analysis"], d["forensic"])
            else:
                _afficher_forensique_doc(d["analysis"], d["forensic"])

    with tab3:
        st.subheader("Verdict global et rapport")
        maths = st.session_state.get("maths_results")
        if maths is None or len(maths) != len(docs_meta):
            st.warning("⚠️ Consultez d'abord l'onglet « Cohérence financière ».")
            return

        docs = [DocumentAnalyse(nom_fichier=d["nom"], type_document=d["type"],
                                analysis=d["analysis"], forensic=d["forensic"], math=m)
                for d, m in zip(docs_meta, maths)]

        cross: Optional[CrossDocResult] = None
        if est_dossier:
            cross = analyser_dossier_croise(docs)
            verdict = calculer_verdict_dossier(docs, cross)
        else:
            verdict = calculer_verdict(maths[0], docs_meta[0]["forensic"])

        colors_map = {"🔴": "#dc2626", "🟠": "#d97706", "🟢": "#16a34a"}
        color = colors_map.get(verdict.statut[0], "#94a3b8")

        st.markdown(f"""
        <div style="background:linear-gradient(135deg,{color}22,{color}11);border:2px solid {color};
                    border-radius:10px;padding:20px;margin-bottom:20px">
            <h3 style="color:{color};margin:0">{verdict.statut}</h3>
            <p style="color:#64748b;margin:8px 0 0 0">Score de risque :
            <strong style="color:{color}">{verdict.score_risque}/100</strong></p>
        </div>
        """, unsafe_allow_html=True)

        st.progress(verdict.score_risque / 100)
        st.caption("ℹ️ Indice d'anomalie **technique du/des document(s)** — ne préjuge ni de la "
                   "solvabilité ni de l'honnêteté du candidat. La décision finale appartient au bailleur.")

        if est_dossier and cross is not None:
            st.markdown("#### Cohérence entre les documents du dossier")
            if cross.doublons_detectes:
                st.error(f"🔴 Fichiers identiques déposés en double : "
                         f"{', '.join(cross.fichiers_dupliques)}")
            else:
                st.success("✅ Aucun fichier dupliqué détecté")
            if cross.ecarts_fiches_paie:
                for msg in cross.ecarts_fiches_paie:
                    st.warning(f"🟠 {msg}")
            elif sum(1 for d in docs_meta if d["type"] == "Fiche de paie") > 1:
                st.success("✅ Cohérence entre les fiches de paie du dossier")
            st.divider()

        st.markdown("#### Recommandations")
        if verdict.score_risque >= 70:
            st.error("Ce dossier présente des signaux d'alerte techniques importants")
            recs = ["🔴 **Suspendre la décision** — demander l'original au candidat",
                    "🔴 **Vérification humaine complémentaire** (employeur, organisme émetteur)",
                    "🔴 **Décision finale au bailleur** (aucune décision automatisée)"]
        elif verdict.score_risque >= 40:
            st.warning("Ce dossier nécessite une attention particulière")
            recs = ["🟠 **Alerter le bailleur** sur les anomalies",
                    "🟠 **Vérification humaine rapide** avant signature",
                    "🟠 **Demander une explication écrite** au candidat"]
        else:
            st.success("Ce dossier ne présente pas de signaux d'alerte")
            recs = ["🟢 **Dossier conforme** — instruction normale",
                    "🟢 Ce rapport peut servir de **justificatif de diligence**"]
        for rec in recs:
            st.markdown(f"- {rec}")

        st.divider()
        if est_dossier and cross is not None:
            pdf_bytes = build_dossier_report_pdf(verdict, docs, cross)
        else:
            pdf_bytes = build_report_pdf(verdict, docs_meta[0]["forensic"], maths[0])
        filename = get_report_filename(verdict.statut, dossier=est_dossier)

        st.markdown("#### Transmission du rapport")
        st.warning("⚠️ L'email standard n'est pas chiffré et ce rapport contient des données "
                   "personnelles. Privilégiez le **téléchargement** puis une transmission sécurisée.")

        email_client = st.text_input("📧 Adresse email du client :",
                                     placeholder="client@exemple.com", key="email_input")
        col_send, col_dl = st.columns(2)
        with col_send:
            if st.button("🚀 Envoyer par email", key="send_btn", use_container_width=True):
                if not email_client:
                    st.error("❌ Saisissez une adresse email")
                elif not is_valid_email(email_client):
                    st.error("❌ Adresse email invalide")
                elif not secrets.email_expediteur:
                    st.error("❌ Envoi indisponible — secrets email non configurés.")
                else:
                    with st.spinner("📨 Envoi en cours…"):
                        ok, msg = envoyer_rapport(secrets, email_client, pdf_bytes, filename)
                        st.success(msg) if ok else st.error(msg)
        with col_dl:
            st.download_button("⬇️ Télécharger PDF", data=pdf_bytes, file_name=filename,
                               mime="application/pdf", key="dl_btn", use_container_width=True)

        st.divider()
        st.caption("💡 Ce rapport est un outil d'aide à la décision. Il ne constitue pas une "
                   "garantie juridique.")


def main() -> None:
    st.set_page_config(page_title="BailSafe | Expert", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="collapsed")
    st.markdown("""
    <style>
    [data-testid="stMetricValue"] { font-size: 28px; }
    [data-testid="stMetricDelta"] { font-size: 14px; }
    </style>
    """, unsafe_allow_html=True)

    if not check_password():
        st.stop()
    afficher_interface_expert()


if __name__ == "__main__":
    main()
