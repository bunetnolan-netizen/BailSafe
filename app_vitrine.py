"""
BailSafe — Vitrine publique (page principale)
Lancer avec : streamlit run app_vitrine.py
"""

from __future__ import annotations

import re
import smtplib
import unicodedata
import hashlib
import struct
import zlib
from dataclasses import dataclass
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import pdfplumber
import streamlit as st
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PDF_MAX_BYTES = 20 * 1024 * 1024  # 20 Mo max

LOGICIELS_SUSPECTS = frozenset([
    "photoshop", "canva", "ilovepdf", "illustrator", "gimp",
    "pixlr", "paint.net", "affinity", "inkscape", "picsart",
])

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AppSecrets:
    email_expediteur: str
    mot_de_passe_email: str

@dataclass(frozen=True)
class PdfAnalysis:
    texte: str
    metadata: dict
    hash_sha256: str
    xref_count: int
    stream_count: int
    font_names: list[str]
    javascript_present: bool
    embedded_files: bool
    error: Optional[str]

@dataclass(frozen=True)
class ForensicResult:
    fraude_meta: bool
    logiciels_detectes: list[str]
    javascript_suspect: bool
    fichiers_incorpores: bool
    hash_sha256: str
    xref_anormal: bool
    fonts_suspectes: list[str]
    score_risque_forensic: int

@dataclass(frozen=True)
class MathResult:
    est_scan: bool
    net_saisi: float
    nb_mois: int
    cumul_saisi: float
    calcul_theorique: float
    ecart: float
    fraude_math: bool

@dataclass(frozen=True)
class Verdict:
    statut: str
    score_risque: int
    fraude_math: bool
    fraude_meta: bool
    est_scan: bool
    ecart: float

# ---------------------------------------------------------------------------
# Chargement des secrets
# ---------------------------------------------------------------------------

@st.cache_resource
def charger_secrets() -> AppSecrets:
    try:
        return AppSecrets(
            email_expediteur=st.secrets["EMAIL_EXPEDITEUR"],
            mot_de_passe_email=st.secrets["MOT_DE_PASSE_EMAIL"],
        )
    except Exception:
        st.warning("⚠️ Secrets non configurés — mode démo.")
        return AppSecrets(email_expediteur="", mot_de_passe_email="")

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_email(email: str) -> bool:
    return bool(email and EMAIL_PATTERN.fullmatch(email.strip()))

def validate_pdf_size(uploaded_file) -> Optional[str]:
    if uploaded_file.size > PDF_MAX_BYTES:
        return f"Fichier trop volumineux ({uploaded_file.size // (1024*1024)} Mo). Maximum : 20 Mo."
    return None

# ---------------------------------------------------------------------------
# Extraction PDF + analyse forensique avancée
# ---------------------------------------------------------------------------

def _sha256_of_file(uploaded_file) -> str:
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    return hashlib.sha256(raw).hexdigest()

def _count_xref_and_streams(uploaded_file) -> tuple[int, int]:
    """Compte les sections xref et les streams dans le PDF brut."""
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    xref_count = raw.count(b"xref")
    stream_count = raw.count(b"stream\n") + raw.count(b"stream\r\n")
    return xref_count, stream_count

def _detect_javascript(uploaded_file) -> bool:
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    return b"/JavaScript" in raw or b"/JS " in raw

def _detect_embedded_files(uploaded_file) -> bool:
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    return b"/EmbeddedFile" in raw or b"/EmbeddedFiles" in raw

def _extract_font_names(pdf) -> list[str]:
    fonts: list[str] = []
    try:
        for page in pdf.pages:
            for name, obj in (page.mediabox and {}) or {}:
                pass
        # Extraction via le reader pdfplumber
        for page in pdf.pages:
            if hasattr(page, 'chars') and page.chars:
                for ch in page.chars[:50]:
                    fn = ch.get("fontname", "")
                    if fn and fn not in fonts:
                        fonts.append(fn)
    except Exception:
        pass
    return fonts[:20]

def extract_pdf_content(uploaded_file) -> PdfAnalysis:
    error = None
    texte = ""
    metadata: dict = {}
    font_names: list[str] = []

    size_error = validate_pdf_size(uploaded_file)
    if size_error:
        return PdfAnalysis("", {}, "", 0, 0, [], False, False, size_error)

    sha256 = _sha256_of_file(uploaded_file)
    xref_count, stream_count = _count_xref_and_streams(uploaded_file)
    javascript = _detect_javascript(uploaded_file)
    embedded = _detect_embedded_files(uploaded_file)

    try:
        with pdfplumber.open(uploaded_file) as pdf:
            metadata = {k: str(v) for k, v in (pdf.metadata or {}).items()}
            font_names = _extract_font_names(pdf)
            for page in pdf.pages:
                page_text = page.extract_text() or ""
                texte += page_text + "\n"
    except Exception as exc:
        error = str(exc)

    return PdfAnalysis(
        texte=texte,
        metadata=metadata,
        hash_sha256=sha256,
        xref_count=xref_count,
        stream_count=stream_count,
        font_names=font_names,
        javascript_present=javascript,
        embedded_files=embedded,
        error=error,
    )

# ---------------------------------------------------------------------------
# Analyse forensique
# ---------------------------------------------------------------------------

def analyser_forensic(analysis: PdfAnalysis) -> ForensicResult:
    meta_string = " ".join(analysis.metadata.values()).lower()
    logiciels = [l for l in LOGICIELS_SUSPECTS if l in meta_string]
    fraude_meta = len(logiciels) > 0

    # xref anormal : plus de 2 sections = document remanié/reconstruit
    xref_anormal = analysis.xref_count > 2

    # Polices suspectes (ex : polices embarquées par éditeurs graphiques)
    fonts_suspectes = [
        f for f in analysis.font_names
        if any(s in f.lower() for s in ["canva", "photoshop", "adobe", "acroform"])
    ]

    # Score forensique
    score = 0
    if fraude_meta:        score += 40
    if xref_anormal:       score += 20
    if analysis.javascript_present: score += 25
    if analysis.embedded_files:     score += 10
    if fonts_suspectes:    score += 15
    score = min(score, 100)

    return ForensicResult(
        fraude_meta=fraude_meta,
        logiciels_detectes=logiciels,
        javascript_suspect=analysis.javascript_present,
        fichiers_incorpores=analysis.embedded_files,
        hash_sha256=analysis.hash_sha256,
        xref_anormal=xref_anormal,
        fonts_suspectes=fonts_suspectes,
        score_risque_forensic=score,
    )

# ---------------------------------------------------------------------------
# Analyse mathématique
# ---------------------------------------------------------------------------

_RE_NET = re.compile(
    r"(?i)net\s*[àa]\s*payer[^\d]{0,20}([\d\s]{1,8}[.,]\d{2})",
)
_RE_CUMUL = re.compile(
    r"(?i)cumul(?:s)?\s*(?:net|imposable|brut)?[^\d]{0,20}([\d\s]{1,8}[.,]\d{2})",
)

def _parse_montant(raw: str) -> float:
    try:
        return float(raw.replace(" ", "").replace(",", "."))
    except ValueError:
        return 0.0

def construire_math_result(
    texte: str,
    net_override: Optional[float] = None,
    mois_override: Optional[int] = None,
    cumul_override: Optional[float] = None,
) -> tuple[float, float, float]:
    """Retourne (net_extrait, cumul_extrait, valeurs par défaut si non trouvé)."""
    net_m = _RE_NET.search(texte)
    cumul_m = _RE_CUMUL.search(texte)
    net = _parse_montant(net_m.group(1)) if net_m else 0.0
    cumul = _parse_montant(cumul_m.group(1)) if cumul_m else 0.0
    return net, cumul

def analyser_math(
    texte: str,
    net_saisi: float,
    nb_mois: int,
    cumul_saisi: float,
) -> MathResult:
    est_scan = len(texte.strip()) < 20
    if est_scan:
        return MathResult(True, 0, 1, 0, 0, 0, False)

    calcul_theorique = net_saisi * nb_mois
    ecart = abs(cumul_saisi - calcul_theorique)
    # Seuil proportionnel : 8 % du cumul théorique, minimum 100 €
    seuil = max(100.0, calcul_theorique * 0.08)
    fraude_math = ecart > seuil

    return MathResult(
        est_scan=False,
        net_saisi=net_saisi,
        nb_mois=nb_mois,
        cumul_saisi=cumul_saisi,
        calcul_theorique=calcul_theorique,
        ecart=ecart,
        fraude_math=fraude_math,
    )

# ---------------------------------------------------------------------------
# Verdict final
# ---------------------------------------------------------------------------

def calculer_verdict(math: MathResult, forensic: ForensicResult) -> Verdict:
    if math.est_scan:
        statut = "VÉRIFICATION MANUELLE REQUISE"
        score = 70
    elif math.fraude_math and forensic.fraude_meta:
        statut = "CRITIQUE (Falsification détectée)"
        score = 95
    elif forensic.javascript_suspect:
        statut = "CRITIQUE (JavaScript suspect)"
        score = 90
    elif math.fraude_math or forensic.fraude_meta:
        statut = "SUSPECT (Anomalies majeures)"
        score = max(75, forensic.score_risque_forensic)
    elif forensic.xref_anormal:
        statut = "SUSPECT (Structure PDF remaniée)"
        score = 60
    else:
        statut = "FIABLE (Aucune anomalie détectée)"
        score = max(5, forensic.score_risque_forensic)

    return Verdict(
        statut=statut,
        score_risque=score,
        fraude_math=math.fraude_math,
        fraude_meta=forensic.fraude_meta,
        est_scan=math.est_scan,
        ecart=math.ecart,
    )

# ---------------------------------------------------------------------------
# Génération PDF du rapport
# ---------------------------------------------------------------------------

def _sanitize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    for src, dst in {"'": "'", "'": "'", "\u201c": '"', "\u201d": '"',
                     "…": "...", "–": "-", "—": "-"}.items():
        ascii_text = ascii_text.replace(src, dst)
    return ascii_text

def get_report_filename(statut: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "-", statut).strip("-").lower() or "rapport"
    return f"rapport-bailsafe-{safe}.pdf"

def build_report_pdf(verdict: Verdict, forensic: ForensicResult) -> bytes:
    is_suspicious = verdict.score_risque >= 60

    pdf = FPDF()
    pdf.add_page()
    w = pdf.w - 2 * pdf.l_margin

    def h(text: str, size: int = 12, bold: bool = False) -> None:
        pdf.set_font("Helvetica", style="B" if bold else "", size=size)
        pdf.cell(0, 8, _sanitize(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def p(text: str, size: int = 10) -> None:
        pdf.set_font("Helvetica", size=size)
        pdf.multi_cell(w, 6, _sanitize(text))

    h("Rapport d'Audit — BailSafe", size=16, bold=True)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 7, _sanitize("Analyse documentaire et controle de coherence"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(4)

    h(f"Diagnostic : {verdict.statut}", size=12, bold=True)
    p(f"- Score de risque : {verdict.score_risque}/100")
    p(f"- Hash SHA-256 du document : {forensic.hash_sha256[:32]}...")
    p(f"- Sections xref detectees : {forensic.xref_anormal and 'Anormal (>2)' or 'Normal'}")

    if not verdict.est_scan:
        p(f"- Ecart budgetaire observe : {verdict.ecart:.2f} EUR")

    if forensic.logiciels_detectes:
        p(f"- Logiciels d'edition detectes : {', '.join(forensic.logiciels_detectes)}")
    else:
        p("- Aucune signature d'outil d'edition graphique suspecte.")

    if forensic.javascript_suspect:
        p("- ALERTE : Code JavaScript detecte dans le PDF.")
    if forensic.fichiers_incorpores:
        p("- Fichiers incorpores detectes dans le document.")
    if forensic.fonts_suspectes:
        p(f"- Polices suspectes : {', '.join(forensic.fonts_suspectes)}")

    pdf.ln(2)
    h("Appreciation", size=11, bold=True)
    if is_suspicious:
        p("Le dossier presente des elements qui appellent a la prudence. Les incoherences doivent etre traitees comme des signaux d'alerte.")
    else:
        p("Le dossier apparait globalement coherent et ne revele pas d'anomalie majeure.")

    pdf.ln(2)
    h("Actions recommandees", size=11, bold=True)
    if is_suspicious:
        p("- Demander l'original du document ou une piece complementaire.")
        p("- Verifier manuellement les montants avant toute decision.")
        p("- Conserver la trace de ce diagnostic.")
    else:
        p("- Conserver le dossier avec un suivi simple.")
        p("- Utiliser ce rapport comme justificatif de rigueur.")

    pdf.ln(4)
    pdf.set_font("Helvetica", style="I", size=9)
    pdf.multi_cell(w, 5, _sanitize(
        "RGPD : Audit realise en memoire locale. Aucune donnee n'est conservee durablement. "
        "Ce rapport constitue un avis technique consultatif et ne constitue pas une garantie juridique."
    ))

    return bytes(pdf.output(dest="S"))

# ---------------------------------------------------------------------------
# Envoi email
# ---------------------------------------------------------------------------

def envoyer_rapport(
    secrets: AppSecrets,
    email_client: str,
    pdf_bytes: bytes,
    filename: str,
) -> tuple[bool, str]:
    if not secrets.email_expediteur or not secrets.mot_de_passe_email:
        return False, "Secrets SMTP non configurés."
    if not is_valid_email(email_client):
        return False, "Adresse email invalide."

    # Nettoyage strict de l'adresse pour éviter l'injection de headers
    clean_email = email_client.strip().replace("\r", "").replace("\n", "")

    try:
        msg = MIMEMultipart()
        msg["From"] = secrets.email_expediteur
        msg["To"] = clean_email
        msg["Subject"] = "[BailSafe] Rapport d'Audit Locatif"
        msg.attach(MIMEText(
            "Bonjour,\n\nVeuillez trouver ci-joint le rapport d'audit.\n\nCordialement,\nNolan — BailSafe",
            "plain",
        ))
        part = MIMEBase("application", "octet-stream")
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(secrets.email_expediteur, secrets.mot_de_passe_email)
            server.send_message(msg)

        return True, "Rapport envoyé avec succès."
    except smtplib.SMTPAuthenticationError:
        return False, "Authentification SMTP échouée. Vérifiez les secrets."
    except smtplib.SMTPException as exc:
        return False, f"Erreur SMTP : {exc}"
    except Exception as exc:
        return False, f"Erreur inattendue : {exc}"

# ---------------------------------------------------------------------------
# Helpers UI
# ---------------------------------------------------------------------------

def build_home_shortcuts() -> list[dict]:
    return [
        {"title": "Le risque",     "slug": "risque",    "icon": "🚨"},
        {"title": "La solution",   "slug": "solution",  "icon": "💡"},
        {"title": "Rapport type",  "slug": "rapport",   "icon": "📄"},
        {"title": "Sécurité",      "slug": "securite",  "icon": "🔒"},
        {"title": "Mentions",      "slug": "mentions",  "icon": "⚖️"},
    ]

def get_home_section_info(slug: str) -> dict:
    sections = {
        "risque": {
            "title": "Pourquoi sécuriser vos dossiers locatifs ?",
            "content": "Un propriétaire n'a ni le temps ni les outils pour traquer les anomalies documentaires. BailSafe automatise ce travail.",
        },
        "solution": {
            "title": "Notre analyse technique",
            "content": "Pour 20 € par dossier : audit de structure PDF, vérification forensique des métadonnées, cohérence mathématique, rapport PDF sous 24h.",
        },
        "rapport": {
            "title": "Ce que contient l'audit",
            "content": "Hash SHA-256 du document, analyse des sections xref, détection des outils d'édition, écart budgétaire calculé, verdict clair.",
        },
        "securite": {
            "title": "Conformité et confidentialité",
            "content": "Conformément au RGPD, BailSafe n'effectue aucun stockage persistant. L'analyse est volatile : les données sont purgées après traitement.",
        },
        "mentions": {
            "title": "Mentions légales",
            "content": (
                "Éditeur : BailSafe — Nolan Bunet. Contact : bunetnolan@gmail.com\n"
                "Hébergement : Streamlit Community Cloud.\n"
                "BailSafe fournit un avis technique consultatif. Aucune garantie d'impayé. "
                "La décision finale relève de la responsabilité exclusive du bailleur."
            ),
        },
    }
    return sections.get(slug, sections["risque"])

def build_gain_simulation(n: int) -> tuple[int, int, int]:
    return n * 25, min(95, n * 12), n * 180

def build_ai_reply(msg: str) -> str:
    low = msg.lower()
    if any(k in low for k in ["prix", "combien", "coût", "tarif"]):
        return "L'audit coûte 20 € par dossier, rapport PDF inclus."
    if any(k in low for k in ["rapide", "vite", "délai"]):
        return "L'analyse est livrée sous 24 heures, rapport prêt à transmettre."
    if any(k in low for k in ["risque", "sécur", "fraude"]):
        return "BailSafe détecte les incohérences mathématiques, les métadonnées suspectes et la structure interne du PDF."
    return "Je peux vous renseigner sur le coût, le délai ou les méthodes de détection utilisées."

# ---------------------------------------------------------------------------
# Page vitrine
# ---------------------------------------------------------------------------

def inject_styles() -> None:
    st.markdown("""
    <style>
    .bs-card {
        background: var(--background-color, #ffffff);
        border: 1px solid rgba(0,0,0,.08);
        border-radius: 14px;
        padding: 18px 20px;
        margin-bottom: 14px;
        transition: transform .2s ease, box-shadow .2s ease;
    }
    .bs-card:hover { transform: translateY(-3px); box-shadow: 0 12px 28px rgba(0,0,0,.07); }
    .bs-hero {
        background: linear-gradient(140deg, #0f172a 0%, #1e3a8a 100%);
        border-radius: 18px;
        padding: 36px 28px;
        text-align: center;
        border: 2px solid rgba(245,158,11,.85);
    }
    </style>
    """, unsafe_allow_html=True)

def afficher_vitrine() -> None:
    inject_styles()

    st.markdown("""
    <div class="bs-hero">
        <div style="font-size:52px;margin-bottom:8px">🛡️</div>
        <h1 style="color:#fff;margin:0;font-size:2rem;letter-spacing:.5px">BailSafe</h1>
        <p style="color:#cbd5e1;margin-top:6px;font-size:1rem">
            Audit anti-fraude documentaire · Analyse forensique PDF · 20 € par dossier
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<h3 style='text-align:center;margin-top:24px'>Louez en toute sérénité.</h3>", unsafe_allow_html=True)

    if "active_home_category" not in st.session_state:
        st.session_state["active_home_category"] = "risque"

    shortcuts = build_home_shortcuts()
    cols = st.columns(len(shortcuts))
    for col, s in zip(cols, shortcuts):
        with col:
            if st.button(f"{s['icon']} {s['title']}", key=f"sc_{s['slug']}", use_container_width=True):
                st.session_state["active_home_category"] = s["slug"]

    active_slug = st.session_state["active_home_category"]
    info = get_home_section_info(active_slug)

    st.divider()

    if active_slug == "risque":
        st.markdown(f"### {info['title']}")
        c1, c2, c3 = st.columns(3)
        c1.metric("Risque financier", "Élevé", "Impayés en hausse", delta_color="inverse")
        c2.metric("Contrôle visuel seul", "Insuffisant", "Fraudes invisibles", delta_color="inverse")
        c3.metric("Délai d'analyse", "< 24h", "Rapport express")
        st.info(info["content"])

    elif active_slug == "solution":
        st.markdown(f"### {info['title']}")
        st.success(info["content"])
        st.markdown("""
- 🔎 **Forensique** : Hash SHA-256, sections xref, JavaScript, fichiers incorporés.
- 🧮 **Cohérence** : Écart budgétaire avec seuil proportionnel au salaire.
- 📄 **Rapport PDF** : Livrable clair, transmissible, conforme RGPD.
        """)

    elif active_slug == "rapport":
        st.markdown(f"### {info['title']}")
        st.markdown("""
> **📋 Exemple de rapport BailSafe**
> - Statut : 🔴 SUSPECT (Anomalies majeures)
> - Hash SHA-256 : `a3f9c2...` (empreinte unique du fichier)
> - Sections xref : **3 détectées** — structure remaniée
> - Écart budgétaire : **1 240,00 €** (seuil proportionnel dépassé)
> - Logiciel détecté : Adobe Photoshop 2023 dans les métadonnées
        """)

    elif active_slug == "securite":
        st.markdown(f"### {info['title']}")
        st.warning("🛡️ Zéro base de données. Analyse volatile. Données purgées après rapport.")
        st.markdown(info["content"])

    elif active_slug == "mentions":
        st.markdown(f"### {info['title']}")
        st.markdown(info["content"])

    st.divider()
    st.markdown("<h3 style='text-align:center'>Une offre claire</h3>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("Prix", "20 €", "par dossier")
    c2.metric("Délai", "< 24h", "analyse express")
    c3.metric("Livrable", "PDF", "rapport transmissible")

    st.markdown("""
    <div class="bs-card" style="border-left: 4px solid #f59e0b;">
        <h4 style="margin-top:0">Comment ça marche</h4>
        <ol style="margin:0;padding-left:18px;line-height:1.9; color:#1e293b">
            <li>Vous déposez le dossier PDF du candidat</li>
            <li>BailSafe analyse : structure, métadonnées, cohérence financière</li>
            <li>Vous recevez un rapport PDF clair sous 24h</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Simulateur de gain")
    n = st.slider("Dossiers analysés par mois", 1, 20, 5)
    minutes, risk, value = build_gain_simulation(n)
    c1, c2, c3 = st.columns(3)
    c1.metric("Temps économisé", f"{minutes} min")
    c2.metric("Risque réduit (est.)", f"{risk}%")
    c3.metric("Valeur protégée (est.)", f"{value} €")

    st.markdown("### Une question ?")
    user_msg = st.text_input("Posez votre question", placeholder="Combien ça coûte ?")
    if user_msg:
        st.info(build_ai_reply(user_msg))

    with st.expander("❓ FAQ"):
        st.write("**L'audit est-il utile si le dossier semble correct ?**")
        st.write("Oui — certains signes de manipulation sont invisibles à l'œil nu et nécessitent une analyse de la structure interne du PDF.")
        st.write("**Qu'est-ce que l'analyse forensique couvre ?**")
        st.write("Hash SHA-256 (intégrité), sections xref (remaniement), métadonnées (outils d'édition), JavaScript, fichiers incorporés.")
        st.write("**Les données sont-elles stockées ?**")
        st.write("Non. Traitement en mémoire uniquement, conforme RGPD.")

    st.markdown("""
    <div class="bs-card" style="background:#0f172a;border:1px solid #f59e0b;text-align:center;padding:24px">
        <h3 style="color:#fff;margin-top:0">Sécurisez vos dossiers sous 24h</h3>
        <p style="color:#e5e7eb">20 € par dossier · Rapport PDF · Analyse forensique complète</p>
        <div style="display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-top:14px">
            <a href="https://leboncoin.fr/profil/3780fc14-e927-43d6-b826-40c02a3300c2" target="_blank"
               style="background:#f56523;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-weight:600">
               🛒 LeBonCoin
            </a>
            <a href="https://www.facebook.com/share/1KKBK1mfpV/?mibextid=wwXlfr" target="_blank"
               style="background:#2563eb;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;font-weight:600">
               📘 Facebook
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="BailSafe | Audit Locatif",
        page_icon="🛡️",
        layout="centered",
    )
    afficher_vitrine()

if __name__ == "__main__":
    main()
