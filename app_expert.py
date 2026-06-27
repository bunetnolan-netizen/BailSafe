from __future__ import annotations

import hashlib
import re
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple
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
    st.error("❌ pdfplumber not installed. Run: pip install -r requirements_merged.txt")
    st.stop()

try:
    from fpdf import FPDF
except ImportError:
    st.error("❌ fpdf2 not installed. Run: pip install -r requirements_merged.txt")
    st.stop()

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib import colors
except ImportError:
    st.error("❌ reportlab not installed. Run: pip install -r requirements_merged.txt")
    st.stop()

# Configuration logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AppSecrets:
    email_expediteur: str
    mot_de_passe_email: str


@dataclass
class PDFAnalysis:
    texte: str
    metadata: dict
    error: Optional[str] = None


@dataclass
class MathResult:
    est_scan: bool
    ecart: float
    calcul_theorique: float
    net_mensuel: float
    mois_cumules: int
    cumul_imposable: float
    fraude_math: bool


@dataclass
class ForensicResult:
    hash_sha256: str
    xref_anormal: bool
    fraude_meta: bool
    logiciels_detectes: list
    javascript_suspect: bool
    fichiers_incorpores: bool
    fonts_suspectes: list
    score_risque_forensic: int


@dataclass
class Verdict:
    score_risque: int
    statut: str
    date_analyse: str


# ============== LOGIQUE MÉTIER ==============

def extract_pdf_content(fichier_pdf) -> PDFAnalysis:
    """Extrait texte, métadonnées et hash du PDF avec pdfplumber."""
    try:
        pdf_bytes = fichier_pdf.read()
        
        # Hash SHA-256
        hash_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
        
        # Parse PDF avec pdfplumber
        texte = ""
        metadata_dict = {}
        
        with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
            # Métadonnées
            if pdf.metadata:
                metadata_dict = {
                    "Auteur": str(pdf.metadata.get("Author", "N/A"))[:50],
                    "Créateur": str(pdf.metadata.get("Creator", "N/A"))[:50],
                    "Producteur": str(pdf.metadata.get("Producer", "N/A"))[:50],
                    "Date création": str(pdf.metadata.get("CreationDate", "N/A"))[:50],
                    "Date modif": str(pdf.metadata.get("ModDate", "N/A"))[:50],
                }
            
            # Texte
            for page in pdf.pages:
                texte += page.extract_text() or ""
        
        return PDFAnalysis(
            texte=texte,
            metadata=metadata_dict,
            error=None
        )
    except Exception as e:
        logger.error(f"Erreur extraction PDF: {str(e)}")
        return PDFAnalysis(
            texte="",
            metadata={},
            error=f"Lecture partielle : {str(e)[:50]}"
        )


def construire_math_result(texte: str) -> Tuple[float, float]:
    """Extrait Net à payer et Cumul imposable du texte."""
    net = 0.0
    cumul = 0.0
    
    # Cherche patterns "Net à payer" ou "Net mensuel"
    patterns_net = [
        r"Net\s+(?:à\s+payer|mensuel)[:\s]+([0-9]+[.,][0-9]{2})",
        r"Net[:\s]+([0-9]+[.,][0-9]{2})",
    ]
    for p in patterns_net:
        match = re.search(p, texte, re.IGNORECASE)
        if match:
            net = float(match.group(1).replace(",", "."))
            break
    
    # Cherche "Cumul imposable"
    patterns_cumul = [
        r"Cumul\s+imposable[:\s]+([0-9]+[.,][0-9]{2})",
        r"Total\s+imposable[:\s]+([0-9]+[.,][0-9]{2})",
    ]
    for p in patterns_cumul:
        match = re.search(p, texte, re.IGNORECASE)
        if match:
            cumul = float(match.group(1).replace(",", "."))
            break
    
    return net, cumul


def analyser_math(texte: str, net_mensuel: float, nb_mois: int, cumul_saisi: float) -> MathResult:
    """Analyse cohérence mathématique."""
    calcul_theo = net_mensuel * nb_mois
    ecart = abs(cumul_saisi - calcul_theo)
    seuil = max(100.0, calcul_theo * 0.08)
    fraude = ecart > seuil
    
    return MathResult(
        est_scan=False,
        ecart=ecart,
        calcul_theorique=calcul_theo,
        net_mensuel=net_mensuel,
        mois_cumules=nb_mois,
        cumul_imposable=cumul_saisi,
        fraude_math=fraude
    )


def analyser_forensic(analysis: PDFAnalysis) -> ForensicResult:
    """Analyse forensique du PDF."""
    texte = analysis.texte.lower()
    metadata = analysis.metadata
    
    # Outils d'édition détectés
    outils_suspects = ["adobe", "indesign", "photoshop", "gimp", "canva", "affinity"]
    logiciels = []
    for key in ["Créateur", "Producteur"]:
        creator = metadata.get(key, "")
        if creator:
            for outil in outils_suspects:
                if outil in creator.lower():
                    logiciels.append(outil.capitalize())
    
    # JavaScript
    javascript = "/JavaScript" in str(metadata) or "javascript" in texte
    
    # Fichiers incorporés
    fichiers_inc = "/EmbeddedFile" in str(metadata)
    
    # Fonts suspectes
    fonts_sus = []
    if "wingdings" in texte or "symbol" in texte:
        fonts_sus.append("Wingdings/Symbol")
    
    # Score forensique
    score = 0
    if logiciels:
        score += 30
    if javascript:
        score += 25
    if fichiers_inc:
        score += 20
    if fonts_sus:
        score += 15
    
    # SHA-256
    hash_val = hashlib.sha256(str(metadata).encode()).hexdigest()
    
    return ForensicResult(
        hash_sha256=hash_val,
        xref_anormal=False,
        fraude_meta=len(logiciels) > 0,
        logiciels_detectes=logiciels,
        javascript_suspect=javascript,
        fichiers_incorpores=fichiers_inc,
        fonts_suspectes=fonts_sus,
        score_risque_forensic=min(score, 95)
    )


def calculer_verdict(math: MathResult, forensic: ForensicResult) -> Verdict:
    """Calcule verdict global."""
    score_math = 50 if math.fraude_math else 0
    score_forensic = forensic.score_risque_forensic
    score_global = int((score_math + score_forensic) / 2)
    
    if score_global >= 80:
        statut = "🔴 ANOMALIES MAJEURES sur le document — Vérification humaine obligatoire"
    elif score_global >= 50:
        statut = "🟠 ANOMALIES MODÉRÉES sur le document — Vérification humaine recommandée"
    else:
        statut = "🟢 AUCUNE ANOMALIE TECHNIQUE détectée sur le document"
    
    return Verdict(
        score_risque=score_global,
        statut=statut,
        date_analyse=datetime.now().strftime("%d/%m/%Y à %H:%M")
    )


def build_report_pdf(verdict: Verdict, forensic: ForensicResult) -> bytes:
    """Génère un rapport PDF professionnel avec ReportLab."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm)
    
    styles = getSampleStyleSheet()
    
    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#f59e0b'),
        alignment=TA_CENTER,
        spaceAfter=20,
        fontName='Helvetica-Bold'
    )
    
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12,
        fontName='Helvetica-Bold',
        borderColor=colors.HexColor('#f59e0b'),
        borderWidth=2,
        borderPadding=10
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#475569'),
        alignment=TA_LEFT,
        spaceAfter=8
    )
    
    story = []
    
    # En-tête
    story.append(Paragraph("🛡️ BAILSAFE", title_style))
    story.append(Paragraph("Rapport d'Audit Documentaire Anti-Fraude", subtitle_style))
    story.append(Spacer(1, 12))
    
    # Infos rapport
    info_data = [
        ["📅 Date d'analyse", verdict.date_analyse],
        ["🔐 Confidentialité", "Ce rapport est destiné au bailleur uniquement"],
    ]
    info_table = Table(info_data, colWidths=[80*mm, 80*mm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, -1), colors.HexColor('#f9fafb')),
        ('TEXTCOLOR', (0, 0), (1, -1), colors.HexColor('#475569')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))
    
    # Verdict principal
    story.append(Paragraph("VERDICT GLOBAL", header_style))
    
    verdict_data = [
        ["Statut", verdict.statut],
        ["Indice d'anomalie documentaire", f"{verdict.score_risque}/100"],
    ]
    verdict_table = Table(verdict_data, colWidths=[50*mm, 110*mm])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#fef2f2') if verdict.score_risque >= 80 else colors.HexColor('#fff7ed')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 16))
    
    # Analyse forensique
    story.append(Paragraph("ANALYSE FORENSIQUE", header_style))
    
    forensic_data = [
        ["Intégrité du fichier", f"SHA-256: {forensic.hash_sha256[:16]}..."],
        ["Outils d'édition détectés", ", ".join(forensic.logiciels_detectes) or "Aucun"],
        ["JavaScript embarqué", "🔴 Détecté" if forensic.javascript_suspect else "🟢 Non détecté"],
        ["Fichiers incorporés", "🔴 Oui" if forensic.fichiers_incorpores else "🟢 Non"],
        ["Polices suspectes", ", ".join(forensic.fonts_suspectes) or "Aucune"],
        ["Score forensique", f"{forensic.score_risque_forensic}/100"],
    ]
    
    forensic_table = Table(forensic_data, colWidths=[50*mm, 110*mm])
    forensic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f9fafb')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(forensic_table)
    story.append(Spacer(1, 16))
    
    # Recommandations
    story.append(Paragraph("RECOMMANDATIONS", header_style))
    
    if verdict.score_risque >= 80:
        recs = [
            "🔴 Suspendre la décision et demander l'original du document au candidat.",
            "🔴 Procéder à une vérification humaine complémentaire (contact employeur, etc.).",
            "🔴 La décision finale d'accepter ou refuser le dossier appartient au bailleur.",
        ]
    elif verdict.score_risque >= 50:
        recs = [
            "🟠 Alerter le bailleur sur les anomalies détectées.",
            "🟠 Vérification humaine rapide recommandée avant signature.",
            "🟠 Demander une explication écrite au candidat.",
        ]
    else:
        recs = [
            "🟢 Dossier conforme — peut procéder normalement.",
            "🟢 Ce rapport peut servir de justificatif de rigueur.",
        ]
    
    for rec in recs:
        story.append(Paragraph(f"• {rec}", normal_style))
    
    story.append(Spacer(1, 20))
    
    # Avertissement légal
    story.append(Paragraph("AVERTISSEMENT LÉGAL", header_style))
    legal_text = ("Ce rapport est une analyse technique automatisée fournie à titre consultatif. "
                  "Il porte sur l'integrite du document, non sur la personne. Il ne constitue pas une "
                  "garantie juridique et ne vaut pas decision : la decision d'accepter ou de refuser un "
                  "dossier appartient exclusivement au bailleur (aucune decision automatisee au sens de "
                  "l'article 22 du RGPD). BailSafe ne peut etre tenu responsable des decisions prises sur "
                  "la base de ce rapport. Une falsification suivie d'une impression puis d'un nouveau scan "
                  "peut echapper a l'analyse.")
    story.append(Paragraph(legal_text, normal_style))
    
    story.append(Spacer(1, 20))
    
    # Footer
    footer_text = ("Rapport généré par BailSafe — Audit Anti-Fraude Locative<br/>"
                   f"bunetnolan@gmail.com · Sainte-Rose, Guadeloupe<br/>"
                   f"<font size=8>Données supprimées automatiquement sous 30 jours</font>")
    story.append(Paragraph(footer_text, ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#94a3b8'),
        alignment=TA_CENTER,
        spaceAfter=0
    )))
    
    # Construction du PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def get_report_filename(statut: str) -> str:
    """Génère nom fichier selon le verdict."""
    date = datetime.now().strftime("%Y%m%d_%H%M%S")
    if "SUSPECT" in statut:
        return f"BailSafe_ALERTE_{date}.pdf"
    elif "VÉRIFIER" in statut:
        return f"BailSafe_ATTENTION_{date}.pdf"
    else:
        return f"BailSafe_CONFORME_{date}.pdf"


def envoyer_rapport(secrets: AppSecrets, email_dest: str, pdf_bytes: bytes, filename: str) -> Tuple[bool, str]:
    """Envoie le rapport par email."""
    if not secrets.email_expediteur or not secrets.mot_de_passe_email:
        return False, "❌ Secrets email non configurés."
    
    try:
        msg = MIMEMultipart()
        msg['From'] = secrets.email_expediteur
        msg['To'] = email_dest
        msg['Subject'] = "🛡️ Votre rapport BailSafe — Audit anti-fraude"
        
        body = ("Bonjour,\n\n"
                "Veuillez trouver ci-joint votre rapport d'audit documentaire BailSafe.\n\n"
                "Ce rapport est confidentiel et destiné au bailleur uniquement.\n\n"
                "Cordialement,\nNolan — BailSafe")
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Attacher le PDF
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={filename}')
        msg.attach(part)
        
        # Envoi SMTP
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(secrets.email_expediteur, secrets.mot_de_passe_email)
            server.send_message(msg)
        
        logger.info(f"Email envoyé à {email_dest}")
        return True, f"✅ Rapport envoyé à {email_dest}"
    
    except Exception as e:
        logger.error(f"Erreur envoi email: {str(e)}")
        return False, f"❌ Erreur envoi: {str(e)[:60]}"


def is_valid_email(email: str) -> bool:
    """Valide format email."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def get_secrets() -> AppSecrets:
    """Charge les secrets depuis Streamlit."""
    try:
        return AppSecrets(
            email_expediteur=st.secrets["EMAIL_EXPEDITEUR"],
            mot_de_passe_email=st.secrets["MOT_DE_PASSE_EMAIL"],
        )
    except Exception:
        st.warning("⚠️ Secrets non configurés — mode démo.")
        return AppSecrets(email_expediteur="", mot_de_passe_email="")


# ============== INTERFACE STREAMLIT ==============

def afficher_interface_expert() -> None:
    """Interface principale d'analyse expert."""
    
    st.markdown("""
    <div style="background:linear-gradient(140deg,#0f172a,#1e3a8a);border:1px solid #f59e0b;
                border-radius:14px;padding:20px 24px;margin-bottom:24px">
        <h2 style="color:#fff;margin:0 0 4px">🕵️ Cockpit d'Analyse Expert</h2>
        <p style="color:#94a3b8;margin:0;font-size:.9rem">
            Forensique PDF avancée · Cohérence financière · Rapport PDF professionnel
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.caption(
        "🔒 **Traitement RGPD** — Les documents déposés sont analysés en mémoire, "
        "ne sont pas conservés et disparaissent à la fin de la session. "
        "Base légale : intérêt légitime du bailleur + exécution du contrat. "
        "Le rapport est un **avis technique consultatif** : aucune décision automatisée "
        "n'est prise sur les personnes (art. 22 RGPD), la décision finale revient au bailleur. "
        "Pensez à informer le candidat que ses pièces font l'objet d'une vérification."
    )

    secrets = get_secrets()

    with st.expander("💰 Modèle de message client"):
        st.code(
            "Bonjour,\n\n"
            "Afin de lancer l'audit technique de votre dossier, merci de régler les 20 € "
            "d'honoraires via PayPal : paypal.me/NolanBunet/20EUR\n\n"
            "Dès réception du paiement, j'analyse les pièces et vous envoie le rapport PDF sous 24h.\n\n"
            "Cordialement,\nNolan — BailSafe",
            language="text",
        )

    fichier_pdf = st.file_uploader("📂 Déposez le PDF à auditer", type="pdf")

    if fichier_pdf is None:
        st.info("📌 Déposez un fichier PDF pour démarrer l'analyse complète.")
        return

    if "current_pdf_name" not in st.session_state or st.session_state["current_pdf_name"] != fichier_pdf.name:
        with st.spinner("🔍 Extraction et analyse du document en cours…"):
            st.session_state["analysis"] = extract_pdf_content(fichier_pdf)
            st.session_state["current_pdf_name"] = fichier_pdf.name
            st.session_state.pop("forensic_result", None)

    analysis = st.session_state["analysis"]

    if analysis.error:
        st.warning(f"⚠️ Lecture partielle : {analysis.error}")

    if "forensic_result" not in st.session_state:
        st.session_state["forensic_result"] = analyser_forensic(analysis)
    
    forensic = st.session_state["forensic_result"]

    tab1, tab2, tab3 = st.tabs([
        "📊 Cohérence financière",
        "🔎 Forensique PDF",
        "📤 Verdict & Rapport",
    ])

    with tab1:
        st.subheader("Analyse de cohérence mathématique")
        
        est_scan = len(analysis.texte.strip()) < 20

        if est_scan:
            st.warning(
                "⚠️ Aucun texte numérique détecté — PDF scanné ou photo. "
                "Vérification visuelle requise. Saisissez manuellement les montants."
            )
            math = MathResult(True, 0, 1, 0, 0, 0, False)
            st.session_state["math_result"] = math
        else:
            st.markdown("#### Extraction automatique")
            net_auto, cumul_auto = construire_math_result(analysis.texte)

            if net_auto == 0.0:
                st.info("ℹ️ Net à payer non détecté automatiquement.")
            if cumul_auto == 0.0:
                st.info("ℹ️ Cumul imposable non détecté automatiquement.")

            c1, c2, c3 = st.columns(3)
            with c1:
                net_saisi = st.number_input("Net mensuel (€)", value=net_auto, min_value=0.0, step=10.0)
            with c2:
                nb_mois = st.number_input("Mois cumulés", value=1, min_value=1, max_value=36)
            with c3:
                cumul_saisi = st.number_input("Cumul imposable (€)", value=cumul_auto, min_value=0.0, step=10.0)

            math = analyser_math(analysis.texte, net_saisi, int(nb_mois), cumul_saisi)
            st.session_state["math_result"] = math

            seuil = max(100.0, math.calcul_theorique * 0.08)

            st.markdown("#### Résultats de l'analyse")
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Cumul théorique", f"{math.calcul_theorique:.2f} €", 
                         help=f"{net_saisi}€ × {nb_mois} mois")
            with m2:
                st.metric("Écart détecté", f"{math.ecart:.2f} €",
                         delta=f"⚠️ {math.ecart:.2f} €" if math.fraude_math else "✅ OK",
                         delta_color="inverse" if math.fraude_math else "off")
            with m3:
                st.metric("Seuil d'alerte", f"{seuil:.2f} €",
                         help="8% du cumul théorique, minimum 100€")

            st.divider()

            if math.fraude_math:
                st.error(f"🚨 **ALERTE** — Écart de {math.ecart:.2f}€ dépasse le seuil de {seuil:.2f}€")
            else:
                st.success("✅ **CONFORME** — Cohérence mathématique validée")

    with tab2:
        st.subheader("Analyse forensique avancée")
        
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.markdown("**Intégrité du fichier**")
            with st.expander("SHA-256 (cliquer pour voir le hash complet)"):
                st.code(forensic.hash_sha256, language="text")
            
            xref_status = "🔴 Anormal (>2 sections)" if forensic.xref_anormal else "🟢 Normal"
            st.markdown(f"**Sections xref** : {xref_status}")
            st.caption("Plusieurs sections xref = PDF remanié ou reconstruit")

        with col_b:
            st.markdown("**Signaux suspects détectés**")
            
            check_items = [
                ("Outils d'édition graphique", forensic.fraude_meta, 
                 ", ".join(forensic.logiciels_detectes) or "Aucun"),
                ("JavaScript embarqué", forensic.javascript_suspect, ""),
                ("Fichiers incorporés", forensic.fichiers_incorpores, ""),
                ("Polices suspectes", len(forensic.fonts_suspectes) > 0,
                 ", ".join(forensic.fonts_suspectes) or "Aucune"),
            ]
            
            for label, flag, detail in check_items:
                icon = "🔴" if flag else "🟢"
                suffix = f" — {detail}" if detail else ""
                st.markdown(f"{icon} {label}{suffix}")

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
            metadata_display = "\n".join([f"**{k}:** {v}" for k, v in analysis.metadata.items()])
            st.markdown(metadata_display)
        else:
            st.caption("Aucune métadonnée disponible")

    with tab3:
        st.subheader("Verdict global et rapport")
        
        math_r = st.session_state.get("math_result")
        forensic_r = st.session_state.get("forensic_result")

        if math_r is None or forensic_r is None:
            st.warning("⚠️ Veuillez d'abord consulter les onglets précédents.")
            return

        verdict = calculer_verdict(math_r, forensic_r)

        verdict_colors = {
            "🔴": ("#dc2626", "danger"),
            "🟠": ("#d97706", "warning"),
            "🟢": ("#16a34a", "success"),
        }
        
        verdict_icon = verdict.statut[0]
        color, severity = verdict_colors.get(verdict_icon, ("#94a3b8", "info"))

        st.markdown(f"""
        <div style="background:linear-gradient(135deg,{color}22,{color}11);border:2px solid {color};
                    border-radius:10px;padding:20px;margin-bottom:20px">
            <h3 style="color:{color};margin:0">{verdict.statut}</h3>
            <p style="color:#64748b;margin:8px 0 0 0">Score de risque: <strong style="color:{color}">{verdict.score_risque}/100</strong></p>
        </div>
        """, unsafe_allow_html=True)

        st.progress(verdict.score_risque / 100)
        st.caption(
            "ℹ️ Indice d'anomalie **technique du document** — ne préjuge ni de la solvabilité "
            "ni de l'honnêteté du candidat. La décision finale appartient au bailleur."
        )

        st.markdown("#### Recommandations")
        
        if verdict.score_risque >= 80:
            recs = [
                "🔴 **Suspendre la décision** — demander l'original du document au candidat",
                "🔴 **Vérification humaine complémentaire** (contact employeur, etc.)",
                "🔴 **La décision finale appartient au bailleur** (aucune décision automatisée)",
            ]
            st.error("Ce document présente des signaux d'alerte techniques importants")
        elif verdict.score_risque >= 50:
            recs = [
                "🟠 **Alerter le bailleur** sur les anomalies détectées",
                "🟠 **Vérification humaine rapide** recommandée avant signature",
                "🟠 **Demander une explication écrite** au candidat",
            ]
            st.warning("Ce dossier nécessite une attention particulière")
        else:
            recs = [
                "🟢 **Dossier conforme** — Peut procéder normalement",
                "🟢 **Ce rapport** peut servir de justificatif de rigueur",
            ]
            st.success("Ce dossier ne présente pas de signaux d'alerte")

        for rec in recs:
            st.markdown(f"- {rec}")

        st.divider()

        pdf_bytes = build_report_pdf(verdict, forensic_r)
        filename = get_report_filename(verdict.statut)

        st.markdown("#### Transmission du rapport")
        st.warning(
            "⚠️ L'email standard n'est pas chiffré et ce rapport contient des données personnelles. "
            "Privilégiez le **téléchargement** puis une transmission sécurisée, ou n'envoyez qu'à une "
            "adresse de confiance, avec l'accord de la personne concernée."
        )

        email_client = st.text_input(
            "📧 Adresse email du client :",
            placeholder="client@exemple.com",
            key="email_input"
        )

        col_send, col_dl = st.columns(2)
        
        with col_send:
            if st.button("🚀 Envoyer par email", key="send_btn", use_container_width=True):
                if not email_client:
                    st.error("❌ Veuillez saisir une adresse email")
                elif not is_valid_email(email_client):
                    st.error("❌ Adresse email invalide")
                else:
                    with st.spinner("📨 Envoi du rapport en cours…"):
                        ok, msg = envoyer_rapport(secrets, email_client, pdf_bytes, filename)
                        if ok:
                            st.success(msg)
                        else:
                            st.error(msg)

        with col_dl:
            st.download_button(
                label="⬇️ Télécharger PDF",
                data=pdf_bytes,
                file_name=filename,
                mime="application/pdf",
                key="dl_btn",
                use_container_width=True
            )

        st.divider()
        st.caption("💡 **Note** : Ce rapport est un outil d'aide à la décision. "
                  "Il ne constitue pas une garantie juridique.")


def main() -> None:
    """Point d'entrée principal."""
    st.set_page_config(
        page_title="BailSafe | Expert",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    st.markdown("""
    <style>
    [data-testid="stMetricValue"] { font-size: 28px; }
    [data-testid="stMetricDelta"] { font-size: 14px; }
    </style>
    """, unsafe_allow_html=True)
    
    afficher_interface_expert()


if __name__ == "__main__":
    main()
