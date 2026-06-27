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
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib import colors
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


# ============== RAPPORT PDF ==============

def build_report_pdf(verdict: Verdict, forensic: ForensicResult, math: MathResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                 textColor=colors.HexColor('#0f172a'), spaceAfter=6,
                                 alignment=TA_CENTER, fontName='Helvetica-Bold')
    subtitle_style = ParagraphStyle('CustomSubtitle', parent=styles['Normal'], fontSize=12,
                                    textColor=colors.HexColor('#f59e0b'), alignment=TA_CENTER,
                                    spaceAfter=20, fontName='Helvetica-Bold')
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=14,
                                  textColor=colors.HexColor('#1e293b'), spaceAfter=12,
                                  fontName='Helvetica-Bold')
    normal_style = ParagraphStyle('NormalCustom', parent=styles['Normal'], fontSize=10,
                                  textColor=colors.HexColor('#475569'), alignment=TA_LEFT,
                                  spaceAfter=8)

    story = []
    story.append(Paragraph("BAILSAFE", title_style))
    story.append(Paragraph("Rapport d'Audit Documentaire Anti-Fraude", subtitle_style))
    story.append(Spacer(1, 12))

    info_data = [
        ["Date d'analyse", verdict.date_analyse],
        ["Empreinte SHA-256 du fichier", f"{forensic.hash_sha256[:32]}…"],
        ["Confidentialité", "Rapport destiné au bailleur uniquement"],
    ]
    info_table = Table(info_data, colWidths=[60 * mm, 100 * mm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#475569')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8), ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("VERDICT GLOBAL", header_style))
    bg = colors.HexColor('#fef2f2') if verdict.score_risque >= 70 else (
        colors.HexColor('#fff7ed') if verdict.score_risque >= 40 else colors.HexColor('#f0fdf4'))
    verdict_data = [
        ["Statut", verdict.statut],
        ["Indice d'anomalie documentaire", f"{verdict.score_risque}/100"],
    ]
    vt = Table(verdict_data, colWidths=[55 * mm, 105 * mm])
    vt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (1, 0), (1, -1), bg),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10), ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(vt)
    story.append(Spacer(1, 16))

    story.append(Paragraph("ANALYSE FORENSIQUE", header_style))
    forensic_data = [
        ["Empreinte SHA-256", f"{forensic.hash_sha256[:24]}…"],
        ["Sauvegardes successives (xref)",
         f"Oui — {forensic.incremental_updates} (document remanie)" if forensic.xref_anormal
         else "Non — structure d'origine"],
        ["Outils d'édition détectés", ", ".join(forensic.logiciels_detectes) or "Aucun"],
        ["Date de modification postérieure", "Oui" if forensic.date_modifiee else "Non"],
        ["JavaScript embarqué", "Détecté" if forensic.javascript_suspect else "Non"],
        ["Fichiers incorporés", "Oui" if forensic.fichiers_incorpores else "Non"],
        ["Annotations superposées", "Oui" if forensic.annotations_suspectes else "Non"],
        ["Polices détectées", str(len(forensic.fonts_detectees))],
        ["Score forensique", f"{forensic.score_risque_forensic}/100"],
    ]
    ft = Table(forensic_data, colWidths=[60 * mm, 100 * mm])
    ft.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f9fafb')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9), ('TOPPADDING', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(ft)
    story.append(Spacer(1, 16))

    if not math.est_scan and math.calcul_theorique > 0:
        story.append(Paragraph("COHÉRENCE FINANCIÈRE", header_style))
        math_data = [
            ["Net imposable mensuel", f"{math.net_imposable_mensuel:.2f} EUR"],
            ["Mois cumulés", str(math.mois_cumules)],
            ["Cumul théorique attendu", f"{math.calcul_theorique:.2f} EUR"],
            ["Cumul imposable déclaré", f"{math.cumul_imposable:.2f} EUR"],
            ["Écart", f"{math.ecart:.2f} EUR ({'ANOMALIE' if math.fraude_math else 'OK'})"],
        ]
        mt = Table(math_data, colWidths=[60 * mm, 100 * mm])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f9fafb')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 9), ('TOPPADDING', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(mt)
        story.append(Spacer(1, 16))

    story.append(Paragraph("RECOMMANDATIONS", header_style))
    if verdict.score_risque >= 70:
        recs = [
            "Suspendre la décision et demander l'original du document au candidat.",
            "Vérification humaine complémentaire (contact employeur, organisme émetteur).",
            "La décision finale d'accepter ou refuser le dossier appartient au bailleur.",
        ]
    elif verdict.score_risque >= 40:
        recs = [
            "Signaler les anomalies détectées au bailleur.",
            "Vérification humaine rapide recommandée avant signature.",
            "Demander une explication écrite au candidat.",
        ]
    else:
        recs = [
            "Aucune anomalie technique — le dossier peut être instruit normalement.",
            "Ce rapport peut servir de justificatif de diligence.",
        ]
    for rec in recs:
        story.append(Paragraph(f"• {rec}", normal_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("AVERTISSEMENT LÉGAL", header_style))
    legal_text = ("Ce rapport est une analyse technique automatisee fournie a titre consultatif. "
                  "Il porte sur l'integrite et la structure du document, non sur la personne. Il ne "
                  "constitue pas une garantie juridique et ne vaut pas decision : la decision "
                  "d'accepter ou de refuser un dossier appartient exclusivement au bailleur (aucune "
                  "decision automatisee au sens de l'article 22 du RGPD). BailSafe ne peut etre tenu "
                  "responsable des decisions prises sur la base de ce rapport. Une falsification suivie "
                  "d'une impression puis d'un nouveau scan peut echapper a l'analyse.")
    story.append(Paragraph(legal_text, normal_style))
    story.append(Spacer(1, 20))

    footer_text = ("Rapport genere par BailSafe — Audit Anti-Fraude Locative<br/>"
                   "bunetnolan@gmail.com · Sainte-Rose, Guadeloupe<br/>"
                   "<font size=8>Donnees supprimees automatiquement sous 30 jours</font>")
    story.append(Paragraph(footer_text, ParagraphStyle(
        'Footer', parent=styles['Normal'], fontSize=9,
        textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)))

    doc.build(story)
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
