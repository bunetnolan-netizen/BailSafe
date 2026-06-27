from __future__ import annotations

import hashlib
import os
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
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
    xref_anormal: bool               # > 1 = PDF remanié après émission
    fraude_meta: bool
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
    nb_eof = len(re.findall(rb"%%EOF", raw))
    incremental_updates = max(nb_eof, 1)
    xref_anormal = incremental_updates > 1

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
                        if subtype in ("/FreeText", "/Stamp", "/Redact"):
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
    if date_modifiee:
        score += 15
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


def _signal_table(rows, col_widths):
    """rows = list of (label, detail, flag_bool|None, value_text).
    flag None = neutre (info). True = alerte. False = OK."""
    data = []
    styles_extra = []
    for i, (label, detail, flag, value) in enumerate(rows):
        if flag is None:
            badge, bcolor, btext = ROW_ALT, SLATE, value
        elif flag:
            badge, bcolor, btext = HexColor('#FEE2E2'), RED, value or "DÉTECTÉ"
        else:
            badge, bcolor, btext = HexColor('#DCFCE7'), GREEN, value or "OK"
        data.append([label, detail, btext])
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
    nb_signaux = sum([forensic.xref_anormal, forensic.fraude_meta, forensic.date_modifiee,
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

    # --- Analyse forensique ---
    story.append(_section_title("Analyse forensique du fichier", styles))
    story.append(Spacer(1, 6))
    forensic_rows = [
        ("Structure du fichier (xref)",
         f"{forensic.incremental_updates} sauvegarde(s) — "
         + ("document remanié après émission" if forensic.xref_anormal else "structure d'origine"),
         forensic.xref_anormal, "REMANIÉ" if forensic.xref_anormal else "INTÈGRE"),
        ("Outils d'édition graphique",
         ", ".join(forensic.logiciels_detectes) or "Aucun outil de retouche détecté",
         forensic.fraude_meta, None),
        ("Date de modification",
         "Modifié après création" if forensic.date_modifiee else "Cohérente avec la création",
         forensic.date_modifiee, None),
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

    # --- Cohérence financière ---
    if not math.est_scan and math.calcul_theorique > 0:
        story.append(_section_title("Cohérence financière", styles))
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
    legal_text = ("Ce rapport est une analyse technique automatisée fournie à titre consultatif. "
                  "Il porte sur l'intégrité et la structure du document, non sur la personne. Il ne "
                  "constitue pas une garantie juridique et ne vaut pas décision : la décision "
                  "d'accepter ou de refuser un dossier appartient exclusivement au bailleur (aucune "
                  "décision automatisée au sens de l'article 22 du RGPD). BailSafe ne peut être tenu "
                  "responsable des décisions prises sur la base de ce rapport. Une falsification suivie "
                  "d'une impression puis d'un nouveau scan peut échapper à l'analyse. Données "
                  "supprimées automatiquement sous 30 jours.")
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


def get_report_filename(statut: str) -> str:
    date = datetime.now().strftime("%Y%m%d_%H%M%S")
    if statut.startswith("🔴"):
        return f"BailSafe_ALERTE_{date}.pdf"
    elif statut.startswith("🟠"):
        return f"BailSafe_ATTENTION_{date}.pdf"
    return f"BailSafe_CONFORME_{date}.pdf"


# ============== EMAIL ==============

def envoyer_rapport(secrets: AppSecrets, email_dest: str, pdf_bytes: bytes, filename: str) -> Tuple[bool, str]:
    if not secrets.email_expediteur or not secrets.mot_de_passe_email:
        return False, "❌ Secrets email non configurés."
    try:
        msg = MIMEMultipart()
        msg['From'] = secrets.email_expediteur
        msg['To'] = email_dest
        msg['Subject'] = "Votre rapport BailSafe — Audit anti-fraude"
        body = ("Bonjour,\n\n"
                "Veuillez trouver ci-joint votre rapport d'audit documentaire BailSafe.\n\n"
                "Ce rapport est confidentiel et destiné au bailleur uniquement.\n\n"
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
        if pwd == expected:
            st.session_state["auth_ok"] = True
            return True
        st.error("Mot de passe incorrect.")
    return False


# ============== INTERFACE STREAMLIT ==============

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

    fichier_pdf = st.file_uploader("📂 Déposez le PDF à auditer", type="pdf")
    if fichier_pdf is None:
        st.info("📌 Déposez un fichier PDF pour démarrer l'analyse complète.")
        return

    if st.session_state.get("current_pdf_name") != fichier_pdf.name:
        with st.spinner("🔍 Extraction et analyse du document…"):
            analysis = extract_pdf_content(fichier_pdf)
            st.session_state["analysis"] = analysis
            st.session_state["current_pdf_name"] = fichier_pdf.name
            st.session_state["forensic_result"] = analyser_forensic(analysis)
            st.session_state.pop("math_result", None)

    analysis = st.session_state["analysis"]
    forensic = st.session_state["forensic_result"]

    if analysis.error:
        st.warning(f"⚠️ {analysis.error}")

    tab1, tab2, tab3 = st.tabs([
        "📊 Cohérence financière", "🔎 Forensique PDF", "📤 Verdict & Rapport",
    ])

    with tab1:
        st.subheader("Analyse de cohérence mathématique")
        est_scan = len(analysis.texte.strip()) < 20

        if est_scan:
            st.warning("⚠️ Aucun texte numérique détecté — PDF scanné ou photo. "
                       "Saisissez manuellement les montants.")
            math = MathResult(True, 0, 0, 0, 0, 0, False)
        else:
            net_auto, cumul_auto = construire_math_result(analysis.texte)
            if net_auto == 0.0:
                st.info("ℹ️ Net imposable non détecté automatiquement — saisie manuelle.")
            if cumul_auto == 0.0:
                st.info("ℹ️ Cumul imposable non détecté automatiquement — saisie manuelle.")

            c1, c2, c3 = st.columns(3)
            with c1:
                net_saisi = st.number_input("Net imposable mensuel (€)", value=net_auto,
                                            min_value=0.0, step=10.0,
                                            help="Ligne « net imposable » de la fiche de paie")
            with c2:
                nb_mois = st.number_input("Mois cumulés", value=1, min_value=1, max_value=36)
            with c3:
                cumul_saisi = st.number_input("Cumul imposable (€)", value=cumul_auto,
                                              min_value=0.0, step=10.0)

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

        st.session_state["math_result"] = math

    with tab2:
        st.subheader("Analyse forensique avancée")
        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("**Intégrité du fichier**")
            with st.expander("SHA-256 du fichier (empreinte complète)"):
                st.code(forensic.hash_sha256, language="text")
            xref_status = (f"🔴 Anormal — {forensic.incremental_updates} sauvegardes successives"
                           if forensic.xref_anormal else "🟢 Normal (structure d'origine)")
            st.markdown(f"**Sections xref** : {xref_status}")
            st.caption("Plusieurs sections xref = PDF remanié/édité après émission.")
            st.markdown(f"**Date modifiée après création** : "
                        f"{'🔴 Oui' if forensic.date_modifiee else '🟢 Non'}")

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

    with tab3:
        st.subheader("Verdict global et rapport")
        math_r = st.session_state.get("math_result")
        forensic_r = st.session_state.get("forensic_result")
        if math_r is None or forensic_r is None:
            st.warning("⚠️ Consultez d'abord les onglets précédents.")
            return

        verdict = calculer_verdict(math_r, forensic_r)
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
        st.caption("ℹ️ Indice d'anomalie **technique du document** — ne préjuge ni de la solvabilité "
                   "ni de l'honnêteté du candidat. La décision finale appartient au bailleur.")

        st.markdown("#### Recommandations")
        if verdict.score_risque >= 70:
            st.error("Ce document présente des signaux d'alerte techniques importants")
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
        pdf_bytes = build_report_pdf(verdict, forensic_r, math_r)
        filename = get_report_filename(verdict.statut)

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
