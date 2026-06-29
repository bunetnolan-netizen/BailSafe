import streamlit as st
import smtplib
import re
from typing import Tuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

st.set_page_config(
    page_title="BailSafe | Détection de Fraude Documentaire — Analyse Forensique",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
FORMSPREE_ENDPOINT = "https://formspree.io/f/xqevqgjo"
PAYPAL_LINK        = "https://paypal.me/NolanBunet/20EUR"
CONTACT_EMAIL      = "bunetnolan@gmail.com"
MAX_PDF_BYTES      = 10 * 1024 * 1024  # 10 Mo
EMAIL_REGEX        = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def get_secrets() -> Tuple[str, str]:
    email = st.secrets.get("EMAIL_EXPEDITEUR", "") or ""
    pwd   = st.secrets.get("MOT_DE_PASSE_EMAIL", "") or ""
    return email, pwd

def email_valide(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email.strip()))

def envoyer_document(pdf_bytes: bytes, filename: str, client_email: str) -> Tuple[bool, str]:
    """Envoie le PDF client à Nolan par email via Gmail SMTP."""
    if len(pdf_bytes) > MAX_PDF_BYTES:
        return False, f"Fichier trop lourd ({len(pdf_bytes)//1024//1024} Mo). Maximum 10 Mo."
    email_exp, mdp = get_secrets()
    if not email_exp or not mdp:
        return False, "Secrets email non configurés dans secrets.toml."
    try:
        msg = MIMEMultipart()
        msg["From"]    = email_exp
        msg["To"]      = CONTACT_EMAIL
        msg["Subject"] = f"📎 Document BailSafe — {client_email} — {filename}"

        body = (
            f"Nouveau document reçu via BailSafe.\n\n"
            f"Email client : {client_email}\n"
            f"Fichier      : {filename}\n"
            f"Taille       : {len(pdf_bytes)//1024} Ko\n\n"
            f"Le document est en pièce jointe.\n"
            f"Retrouvez la commande correspondante dans Formspree (même email client)."
        )
        msg.attach(MIMEText(body, "plain", "utf-8"))

        part = MIMEBase("application", "octet-stream")
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(email_exp, mdp)
            # Envoi à Nolan
            server.sendmail(email_exp, CONTACT_EMAIL, msg.as_string())
            # Accusé de réception au client
            confirm = MIMEMultipart()
            confirm["From"]    = email_exp
            confirm["To"]      = client_email
            confirm["Subject"] = "✅ BailSafe — Votre document a bien été reçu"
            confirm.attach(MIMEText(
                "Bonjour,\n\n"
                "Votre document a bien été reçu.\n"
                "Nolan vous enverra votre rapport BailSafe sous 24h.\n\n"
                "Cordialement,\nNolan — BailSafe\n"
                "bunetnolan@gmail.com",
                "plain", "utf-8"
            ))
            server.sendmail(email_exp, client_email, confirm.as_string())

        return True, "Document envoyé avec succès."
    except Exception as e:
        return False, str(e)

# ─── SESSION STATE ─────────────────────────────────────────────────────────────
if "document_envoye" not in st.session_state:
    st.session_state.document_envoye = False

# ─── VÉRIFICATION SECRETS AU DÉMARRAGE ────────────────────────────────────────
_email_exp, _mdp = get_secrets()
if not _email_exp or not _mdp:
    st.warning(
        "⚠️ **Configuration incomplète** : `EMAIL_EXPEDITEUR` ou `MOT_DE_PASSE_EMAIL` "
        "absent de `.streamlit/secrets.toml`. L'envoi de documents ne fonctionnera pas.",
        icon="⚠️"
    )

# ─── PAGE HTML (landing + formulaire Formspree) ────────────────────────────────
html_content = f"""
<!DOCTYPE html>
<html lang="fr" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BailSafe | Détection de Fraude Documentaire — Analyse Forensique</title>

    <!-- SEO -->
    <meta name="description" content="BailSafe détecte les fausses fiches de paie et documents falsifiés avant que vous signiez un bail. Analyse forensique PDF complète, rapport sous 24h. 20€ par dossier.">
    <meta name="keywords" content="fraude locative, fausse fiche de paie, vérification dossier locataire, analyse forensique PDF, bailleur, audit documentaire">
    <meta name="robots" content="index, follow">

    <!-- Open Graph -->
    <meta property="og:title" content="BailSafe — Audit anti-fraude pour bailleurs">
    <meta property="og:description" content="Détectez les faux documents avant de signer. Analyse forensique PDF, rapport sous 24h. 20€ par dossier.">
    <meta property="og:type" content="website">
    <meta property="og:locale" content="fr_FR">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="BailSafe — Détectez les faux dossiers locataires">
    <meta name="twitter:description" content="Analyse forensique PDF : SHA-256, métadonnées, cohérence financière. Rapport sous 24h. 20€.">

    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}

        /* NAV */
        nav {{ position: fixed; top: 0; width: 100%; z-index: 50; background: rgba(15,23,42,0.95); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148,163,184,0.1); }}
        .nav-inner {{ max-width: 1400px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; height: 64px; }}
        .logo {{ display: flex; align-items: center; gap: 8px; color: white; font-weight: bold; font-size: 20px; text-decoration: none; }}
        .logo .shield {{ color: #f59e0b; font-size: 24px; }}
        .logo .mark {{ color: #f59e0b; }}
        .nav-links {{ display: none; gap: 32px; }}
        .nav-links a {{ color: #cbd5e1; text-decoration: none; font-size: 14px; font-weight: 500; transition: color 0.2s; }}
        .nav-links a:hover {{ color: #fff; }}
        @media (min-width: 768px) {{ .nav-links {{ display: flex; }} }}
        .nav-cta {{ background: #f59e0b; color: #1e293b; padding: 10px 20px; border-radius: 6px; font-weight: 700; font-size: 13px; border: none; cursor: pointer; display: none; }}
        .nav-cta:hover {{ background: #fbbf24; }}
        @media (min-width: 768px) {{ .nav-cta {{ display: block; }} }}

        /* BURGER */
        .burger {{ display: flex; flex-direction: column; gap: 5px; cursor: pointer; padding: 8px; background: none; border: none; }}
        .burger span {{ display: block; width: 22px; height: 2px; background: #cbd5e1; border-radius: 2px; transition: all 0.3s; }}
        .burger.open span:nth-child(1) {{ transform: translateY(7px) rotate(45deg); }}
        .burger.open span:nth-child(2) {{ opacity: 0; }}
        .burger.open span:nth-child(3) {{ transform: translateY(-7px) rotate(-45deg); }}
        @media (min-width: 768px) {{ .burger {{ display: none; }} }}
        .mobile-menu {{ display: none; position: fixed; top: 64px; left: 0; right: 0; background: rgba(15,23,42,0.98); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148,163,184,0.1); z-index: 49; padding: 20px 24px; flex-direction: column; gap: 16px; }}
        .mobile-menu.open {{ display: flex; }}
        .mobile-menu a {{ color: #cbd5e1; text-decoration: none; font-size: 16px; font-weight: 500; padding: 10px 0; border-bottom: 1px solid rgba(148,163,184,0.1); }}
        .mobile-menu a:last-child {{ border-bottom: none; }}
        .mobile-menu .mobile-cta {{ background: #f59e0b; color: #1e293b; padding: 14px; border-radius: 8px; font-weight: 700; text-align: center; border-bottom: none !important; margin-top: 4px; }}

        /* HERO */
        .hero {{ background: #0f172a; padding: 120px 24px 80px; text-align: center; position: relative; overflow: hidden; }}
        .hero::before {{ content: ''; position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 1000px; height: 500px; background: radial-gradient(ellipse, rgba(245,158,11,0.15), transparent 70%); pointer-events: none; }}
        .hero-content {{ max-width: 800px; margin: 0 auto; position: relative; z-index: 1; }}
        .h-badge {{ display: inline-block; background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: #fbbf24; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; letter-spacing: 1px; margin-bottom: 24px; text-transform: uppercase; }}
        .h-title {{ font-size: clamp(2rem,6vw,3.5rem); font-weight: 800; color: #fff; margin-bottom: 20px; line-height: 1.15; }}
        .h-title .accent {{ background: linear-gradient(135deg,#f59e0b,#ff6b6b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
        .h-sub {{ font-size: 1.15rem; color: #cbd5e1; max-width: 650px; margin: 0 auto 32px; line-height: 1.7; }}
        .h-buttons {{ display: flex; flex-direction: column; gap: 12px; justify-content: center; margin-bottom: 20px; }}
        @media (min-width: 640px) {{ .h-buttons {{ flex-direction: row; }} }}
        .btn-primary {{ background: #f59e0b; color: #1e293b; padding: 14px 28px; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; box-shadow: 0 4px 12px rgba(245,158,11,0.25); font-size: 16px; transition: all 0.2s; }}
        .btn-primary:hover {{ background: #fbbf24; transform: translateY(-2px); }}
        .btn-secondary {{ background: transparent; color: #f59e0b; border: 1px solid rgba(245,158,11,0.4); padding: 14px 28px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .btn-secondary:hover {{ border-color: rgba(245,158,11,0.7); background: rgba(245,158,11,0.05); }}
        .h-proof {{ display: flex; gap: 30px; justify-content: center; flex-wrap: wrap; font-size: 13px; color: #94a3b8; }}
        .h-proof span {{ color: #f59e0b; }}

        /* SCANNER */
        .scanner-demo {{ max-width: 800px; margin: 0 auto; padding: 0 24px; }}
        .scan-container {{ background: #fff; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.12); overflow: hidden; border: 1px solid #e2e8f0; }}
        @keyframes scanline {{ 0% {{ top:0;opacity:0; }} 10% {{ opacity:1; }} 90% {{ opacity:1; }} 100% {{ top:100%;opacity:0; }} }}
        .scan-header {{ background: #f1f5f9; padding: 16px 24px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 12px; }}
        .scan-dots {{ display: flex; gap: 8px; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; }}
        .dot-r {{ background: #ef4444; }} .dot-y {{ background: #f59e0b; }} .dot-g {{ background: #10b981; }}
        .scan-name {{ font-size: 12px; color: #64748b; font-weight: 600; margin-left: 8px; }}
        .scan-body {{ padding: 24px; position: relative; min-height: 280px; }}
        .scan-row {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }}
        .scan-row:last-child {{ border-bottom: none; }}
        .scan-label {{ color: #64748b; font-weight: 500; }}
        .badge-ok {{ background: #ecfdf5; color: #065f46; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .badge-alert {{ background: #fef2f2; color: #991b1b; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .badge-warn {{ background: #fef3c7; color: #92400e; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .scan-score {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #f1f5f9; }}
        .score-label {{ display: flex; justify-content: space-between; font-size: 12px; color: #64748b; margin-bottom: 8px; }}
        .score-num {{ font-size: 24px; font-weight: 800; color: #ef4444; }}
        .score-bar {{ height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; }}
        .score-fill {{ height: 100%; width: 0%; background: linear-gradient(90deg,#f59e0b,#ef4444); border-radius: 3px; transition: width 2.2s cubic-bezier(0.16,1,0.3,1); }}
        .verdict {{ margin-top: 16px; padding: 12px 16px; background: #fef2f2; border-left: 3px solid #ef4444; color: #7f1d1d; font-size: 12px; border-radius: 4px; opacity: 0; transition: opacity 0.4s; font-weight: 600; }}
        .scanner-line {{ position: absolute; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg,transparent,#ef4444,transparent); box-shadow: 0 0 8px #ef4444; animation: scanline 2.8s ease-in-out infinite; z-index: 10; }}

        /* SECTIONS */
        .section {{ padding: 80px 24px; max-width: 1400px; margin: 0 auto; }}
        .s-label {{ font-size: 12px; letter-spacing: 2px; text-transform: uppercase; color: #f59e0b; font-weight: 700; margin-bottom: 16px; }}
        .s-title {{ font-size: clamp(2rem,5vw,3rem); font-weight: 800; color: #0f172a; margin-bottom: 16px; line-height: 1.2; }}
        .s-title .accent {{ color: #f59e0b; }}
        .s-desc {{ font-size: 1.05rem; color: #475569; max-width: 700px; line-height: 1.8; margin-bottom: 32px; }}

        /* PAIN */
        .pain-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap: 16px; margin-top: 32px; }}
        .pain-card {{ background: #fff; border: 1px solid #e2e8f0; border-left: 4px solid #ef4444; border-radius: 8px; padding: 24px; transition: all 0.2s; }}
        .pain-card:hover {{ transform: translateY(-4px); box-shadow: 0 12px 24px rgba(0,0,0,0.08); }}
        .pain-num {{ font-size: 28px; font-weight: 800; color: #f59e0b; margin-bottom: 8px; }}
        .pain-title {{ font-weight: 700; color: #0f172a; margin-bottom: 8px; font-size: 15px; }}
        .pain-desc {{ font-size: 14px; color: #64748b; line-height: 1.6; }}

        /* BENEFITS */
        .benefits-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); gap: 16px; margin-top: 32px; }}
        .benefit-card {{ background: linear-gradient(135deg,#f9fafb,#f3f4f6); border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; text-align: center; transition: all 0.2s; }}
        .benefit-card:hover {{ border-color: #f59e0b; background: #fffbf0; }}
        .b-icon {{ font-size: 28px; margin-bottom: 12px; }}
        .b-title {{ font-weight: 700; color: #0f172a; margin-bottom: 8px; font-size: 15px; }}
        .b-desc {{ font-size: 13px; color: #64748b; line-height: 1.6; }}

        /* PROCESS */
        .process {{ margin-top: 48px; background: #f9fafb; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }}
        .process-head {{ background: #0f172a; color: #fff; padding: 16px 24px; font-size: 12px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }}
        .process-steps {{ padding: 32px 24px; display: flex; flex-direction: column; gap: 24px; }}
        @media (min-width: 768px) {{ .process-steps {{ flex-direction: row; justify-content: space-around; }} }}
        .p-step {{ display: flex; flex-direction: column; align-items: center; text-align: center; }}
        .p-num {{ width: 40px; height: 40px; background: #f59e0b; color: #1e293b; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 800; margin-bottom: 12px; font-size: 18px; }}
        .p-name {{ font-weight: 700; color: #0f172a; margin-bottom: 6px; font-size: 15px; }}
        .p-desc {{ font-size: 13px; color: #64748b; line-height: 1.6; }}

        /* EXPERT */
        .report-section {{ background: #f9fafb; border-radius: 8px; padding: 24px; margin-top: 32px; border: 1px solid #e2e8f0; }}
        .r-head {{ font-size: 12px; color: #64748b; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 16px; }}
        .r-rows {{ display: flex; flex-direction: column; gap: 12px; }}
        .r-row {{ display: grid; grid-template-columns: 1fr auto; gap: 16px; font-size: 13px; padding: 8px 0; }}
        .r-label {{ color: #64748b; }}
        .r-val {{ font-weight: 700; font-family: 'Courier New', monospace; }}
        .v-red {{ color: #dc2626; }} .v-orange {{ color: #d97706; }} .v-green {{ color: #16a34a; }}
        .author-box {{ background: #fffbf0; border: 1px solid #fed7aa; border-radius: 8px; padding: 20px; margin-top: 24px; display: flex; gap: 16px; }}
        .author-avatar {{ width: 48px; height: 48px; background: #f59e0b; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 16px; flex-shrink: 0; }}
        .author-text {{ font-size: 14px; color: #78350f; line-height: 1.6; }}
        .author-text strong {{ color: #b45309; }}

        /* FAQ */
        .faq-section {{ margin-top: 48px; }}
        .faq-item {{ border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 8px; overflow: hidden; background: #fff; }}
        .faq-q {{ padding: 18px 20px; font-weight: 700; color: #0f172a; cursor: pointer; display: flex; justify-content: space-between; align-items: center; font-size: 15px; user-select: none; }}
        .faq-q:hover {{ background: #f9fafb; }}
        .faq-icon {{ color: #f59e0b; font-size: 18px; transition: transform 0.3s; flex-shrink: 0; margin-left: 12px; }}
        .faq-item.open .faq-icon {{ transform: rotate(45deg); }}
        .faq-a {{ display: none; padding: 14px 20px 18px; font-size: 14px; color: #475569; line-height: 1.7; border-top: 1px solid #f1f5f9; }}
        .faq-item.open .faq-a {{ display: block; }}

        /* OFFER */
        .offer-box {{ background: #0f172a; border-radius: 12px; overflow: hidden; margin-top: 32px; border: 1px solid rgba(245,158,11,0.2); }}
        .offer-head {{ background: linear-gradient(135deg,#1e293b,#0f172a); padding: 32px 24px; text-align: center; }}
        .offer-price {{ font-size: 3.5rem; font-weight: 800; color: #fff; margin-bottom: 4px; }}
        .offer-unit {{ font-size: 14px; color: #cbd5e1; }}
        .offer-tag {{ display: inline-block; background: rgba(245,158,11,0.15); color: #fbbf24; padding: 6px 16px; border-radius: 6px; font-size: 12px; font-weight: 700; margin-top: 12px; border: 1px solid rgba(245,158,11,0.3); }}
        .offer-body {{ padding: 32px 24px; }}
        .objections {{ display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }}
        .obj-item {{ display: flex; gap: 12px; font-size: 14px; color: #cbd5e1; align-items: flex-start; }}
        .obj-check {{ color: #10b981; font-weight: 800; font-size: 18px; flex-shrink: 0; margin-top: -2px; }}
        .offer-buttons {{ display: flex; flex-direction: column; gap: 12px; }}
        .btn-final {{ background: #f59e0b; color: #1e293b; padding: 16px; border: none; border-radius: 8px; font-weight: 800; font-size: 15px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(245,158,11,0.25); width: 100%; }}
        .btn-final:hover {{ background: #fbbf24; transform: translateY(-2px); }}
        .btn-secondary-final {{ background: transparent; color: #cbd5e1; border: 1px solid rgba(245,158,11,0.3); padding: 14px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; width: 100%; }}
        .btn-secondary-final:hover {{ border-color: rgba(245,158,11,0.6); color: #fff; }}
        .garantie {{ background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; padding: 14px; font-size: 12px; color: #047857; margin-top: 16px; line-height: 1.6; }}
        .form-divider {{ display: flex; align-items: center; gap: 16px; margin: 28px 0; color: #94a3b8; font-size: 13px; }}
        .form-divider::before, .form-divider::after {{ content: ''; flex: 1; height: 1px; background: rgba(148,163,184,0.2); }}

        /* FORM */
        .form-box {{ background: #1e293b; border: 1px solid rgba(245,158,11,0.25); border-radius: 10px; padding: 28px 24px; }}
        .form-box-title {{ font-size: 15px; font-weight: 700; color: #fff; margin-bottom: 6px; }}
        .form-box-sub {{ font-size: 13px; color: #94a3b8; margin-bottom: 20px; }}
        .form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
        @media (max-width: 600px) {{ .form-grid {{ grid-template-columns: 1fr; }} }}
        .form-full {{ grid-column: 1 / -1; }}
        .f-label {{ display: block; font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px; letter-spacing: 0.5px; text-transform: uppercase; }}
        .f-input, .f-select, .f-textarea {{ width: 100%; background: #0f172a; border: 1px solid rgba(148,163,184,0.2); border-radius: 6px; padding: 11px 14px; color: #fff; font-size: 14px; font-family: 'Inter', sans-serif; outline: none; }}
        .f-input:focus, .f-select:focus, .f-textarea:focus {{ border-color: rgba(245,158,11,0.6); }}
        .f-input::placeholder, .f-textarea::placeholder {{ color: #475569; }}
        .f-select option {{ background: #1e293b; }}
        .f-textarea {{ resize: vertical; min-height: 90px; }}
        .gdpr-checkbox {{ display: flex; align-items: flex-start; gap: 12px; margin: 16px 0; padding: 12px; background: rgba(16,185,129,0.05); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; }}
        .gdpr-checkbox input {{ margin-top: 2px; cursor: pointer; accent-color: #f59e0b; }}
        .gdpr-checkbox label {{ font-size: 12px; color: #475569; cursor: pointer; line-height: 1.5; }}
        .gdpr-checkbox a {{ color: #f59e0b; font-weight: 600; text-decoration: none; border-bottom: 1px dotted; }}
        .btn-form-submit {{ width: 100%; background: #f59e0b; color: #1e293b; padding: 15px; border: none; border-radius: 8px; font-weight: 800; font-size: 15px; cursor: pointer; margin-top: 6px; box-shadow: 0 4px 12px rgba(245,158,11,0.25); transition: all 0.2s; }}
        .btn-form-submit:hover:not(:disabled) {{ background: #fbbf24; transform: translateY(-2px); }}
        .btn-form-submit:disabled {{ opacity: 0.6; cursor: not-allowed; }}

        /* PAYMENT CONFIRM */
        .payment-confirm {{ display: none; background: #0f172a; border: 1px solid rgba(16,185,129,0.3); border-radius: 10px; padding: 32px 24px; text-align: center; margin-top: 16px; }}
        .payment-confirm.visible {{ display: block; }}
        .pc-icon {{ font-size: 40px; margin-bottom: 16px; }}
        .pc-title {{ font-size: 20px; font-weight: 800; color: #fff; margin-bottom: 8px; }}
        .pc-sub {{ font-size: 14px; color: #94a3b8; margin-bottom: 24px; line-height: 1.7; }}
        .num-commande-box {{ background: #1e293b; border: 1px solid rgba(245,158,11,0.4); border-radius: 8px; padding: 14px 20px; margin-bottom: 20px; font-family: 'Courier New', monospace; font-size: 20px; font-weight: 800; color: #f59e0b; letter-spacing: 2px; }}
        .num-commande-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }}
        .btn-paypal {{ background: #003087; color: #fff; padding: 16px 20px; border: none; border-radius: 8px; font-weight: 700; font-size: 15px; cursor: pointer; transition: all 0.2s; width: 100%; margin-bottom: 12px; }}
        .btn-paypal:hover {{ background: #00409a; transform: translateY(-2px); }}
        .scroll-hint {{ background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.25); border-radius: 8px; padding: 14px 18px; font-size: 13px; color: #fbbf24; line-height: 1.6; margin-top: 12px; }}
        .pc-note {{ font-size: 12px; color: #64748b; margin-top: 12px; }}

        /* TOAST */
        .toast {{ position: fixed; bottom: 24px; right: 24px; background: #1e293b; border: 1px solid rgba(245,158,11,0.4); color: #fff; padding: 14px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; z-index: 9999; transform: translateY(80px); opacity: 0; transition: all 0.35s; max-width: 320px; }}
        .toast.show {{ transform: translateY(0); opacity: 1; }}
        .toast.error {{ border-color: rgba(239,68,68,0.5); }}

        /* FOOTER */
        .footer {{ background: #0f172a; color: #94a3b8; padding: 32px 24px; text-align: center; border-top: 1px solid rgba(148,163,184,0.1); font-size: 13px; }}
        .footer-logo {{ color: #fff; font-weight: 700; margin-bottom: 8px; }}
        .footer-logo .mark {{ color: #f59e0b; }}
        .footer-links {{ display: flex; justify-content: center; gap: 16px; flex-wrap: wrap; margin-top: 12px; font-size: 12px; }}
        .footer-links a {{ color: #94a3b8; text-decoration: none; transition: color 0.2s; }}
        .footer-links a:hover {{ color: #f59e0b; }}
    </style>
</head>
<body>

    <!-- NAV -->
    <nav>
        <div class="nav-inner">
            <a href="#" class="logo">
                <span class="fa-solid fa-shield-halved shield"></span>
                <span>Bail<span class="mark">Safe</span></span>
            </a>
            <div class="nav-links">
                <a href="#pain">Le Risque</a>
                <a href="#benefits">La Solution</a>
                <a href="#expert">L'Expertise</a>
                <a href="#faq">FAQ</a>
                <a href="#offer">Tarif</a>
            </div>
            <button class="nav-cta" onclick="document.getElementById('offer').scrollIntoView({{behavior:'smooth'}})">Sécuriser un dossier</button>
            <button class="burger" id="burger" onclick="toggleMenu()" aria-label="Menu">
                <span></span><span></span><span></span>
            </button>
        </div>
    </nav>

    <!-- MOBILE MENU -->
    <div class="mobile-menu" id="mobileMenu">
        <a href="#pain" onclick="closeMenu()">Le Risque</a>
        <a href="#benefits" onclick="closeMenu()">La Solution</a>
        <a href="#expert" onclick="closeMenu()">L'Expertise</a>
        <a href="#faq" onclick="closeMenu()">FAQ</a>
        <a href="#offer" onclick="closeMenu()">Tarif</a>
        <a href="#offer" class="mobile-cta" onclick="closeMenu()">Sécuriser un dossier — 20 €</a>
    </div>

    <!-- HERO -->
    <section class="hero">
        <div class="hero-content">
            <div class="h-badge">Service exclusif pour propriétaires bailleurs</div>
            <h1 class="h-title">Ne donnez pas les clés de votre bien à un <span class="accent">fraudeur</span> (sans le savoir).</h1>
            <p class="h-sub">Les fausses fiches de paie et avis d'imposition falsifiés sont devenus indétectables à l'œil nu. BailSafe détecte ces anomalies grâce à une analyse forensique avancée des PDF — évitez jusqu'à 3 ans de procédure d'expulsion et des milliers d'euros de pertes.</p>
            <div class="h-buttons">
                <button class="btn-primary" onclick="document.getElementById('offer').scrollIntoView({{behavior:'smooth'}})">Analyser un dossier maintenant (20€)</button>
                <button class="btn-secondary" onclick="document.getElementById('expert').scrollIntoView({{behavior:'smooth'}})">Voir un exemple de rapport</button>
            </div>
            <div class="h-proof">
                <div><span>⚡ Résultat sous 24h</span></div>
                <div><span>📊 Investissement 100% déductible</span></div>
                <div><span>✓ Conforme RGPD</span></div>
            </div>
        </div>
    </section>

    <!-- SCANNER DEMO -->
    <div class="scanner-demo">
        <div class="scan-container">
            <div class="scan-header">
                <div class="scan-dots">
                    <div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div>
                </div>
                <span class="scan-name">Analyse BailSafe en cours...</span>
            </div>
            <div class="scan-body">
                <div class="scan-row"><span class="scan-label">SHA-256 intégrité</span><span class="badge-ok">VÉRIFIÉ</span></div>
                <div class="scan-row"><span class="scan-label">Sections xref</span><span class="badge-warn">ANORMAL (3)</span></div>
                <div class="scan-row"><span class="scan-label">Métadonnées éditeur</span><span class="badge-alert">Adobe Photoshop 2023</span></div>
                <div class="scan-row"><span class="scan-label">Écart budgétaire</span><span class="badge-alert">1 240 € / DÉPASSÉ</span></div>
                <div class="scan-row"><span class="scan-label">JavaScript embarqué</span><span class="badge-ok">AUCUN</span></div>
                <div class="scan-score">
                    <div class="score-label"><span>Score de risque</span><span class="score-num" id="scorenum">0</span></div>
                    <div class="score-bar"><div class="score-fill" id="scorefill"></div></div>
                    <div class="verdict" id="verd">⚠️ ANOMALIES DÉTECTÉES — Vérification humaine recommandée avant toute décision.</div>
                </div>
                <div class="scanner-line"></div>
            </div>
        </div>
    </div>

    <!-- PAIN -->
    <section class="section" id="pain">
        <div class="s-label">// Le_Problème</div>
        <h2 class="s-title">Vous contrôlez à l'œil nu. <span class="accent">Les fraudeurs le savent.</span></h2>
        <p class="s-desc">Les fausses fiches de paie, avis d'imposition modifiés et contrats bidons ne se voient plus. Ils sont générés en PDF propre, avec des outils gratuits accessibles à tous.</p>
        <div class="pain-grid">
            <div class="pain-card"><div class="pain-num">01</div><div class="pain-title">Un impayé = ~3 000 € de pertes minimum</div><div class="pain-desc">Avant toute procédure légale. Sans compter les mois de vacance locative et les frais d'huissier.</div></div>
            <div class="pain-card"><div class="pain-num">02</div><div class="pain-title">Un montant modifié est invisible à l'œil nu</div><div class="pain-desc">Le chiffre semble juste, la mise en page aussi. Seule une analyse forensique trahit la manipulation.</div></div>
            <div class="pain-card"><div class="pain-num">03</div><div class="pain-title">Une fois le bail signé, vous êtes bloqué</div><div class="pain-desc">L'expulsion prend 12 à 18 mois. Un dossier non vérifié vous coûtera bien plus que 20 €.</div></div>
            <div class="pain-card"><div class="pain-num">04</div><div class="pain-title">Faire confiance à son instinct = roulette</div><div class="pain-desc">Les fraudeurs sont polis, bien préparés, et suivent des tutoriels pour falsifier leurs documents.</div></div>
        </div>
    </section>

    <!-- BENEFITS -->
    <section class="section" id="benefits">
        <div class="s-label">// La_Solution</div>
        <h2 class="s-title">Ce que BailSafe analyse <span class="accent">en moins de 24h.</span></h2>
        <p class="s-desc">Pas de formulaire compliqué, pas de spécialiste à convaincre. Vous déposez le PDF — BailSafe inspecte la structure profonde et vous livre un verdict clair.</p>
        <div class="benefits-grid">
            <div class="benefit-card"><div class="b-icon">🔬</div><div class="b-title">Forensique métadonnées</div><div class="b-desc">Détecte Photoshop, Canva et outils d'édition cachés dans la structure du PDF.</div></div>
            <div class="benefit-card"><div class="b-icon">🔐</div><div class="b-title">Intégrité SHA-256</div><div class="b-desc">Empreinte unique — prouve que le document n'a pas été altéré après émission.</div></div>
            <div class="benefit-card"><div class="b-icon">💰</div><div class="b-title">Cohérence budgétaire</div><div class="b-desc">Vérifie automatiquement si les cumuls de salaire correspondent aux mensualités.</div></div>
            <div class="benefit-card"><div class="b-icon">📄</div><div class="b-title">Rapport PDF transmissible</div><div class="b-desc">Document daté, conservable, utile en cas de litige ou refus motivé.</div></div>
        </div>
        <div class="process">
            <div class="process-head">Procédure — 3 Étapes</div>
            <div class="process-steps">
                <div class="p-step"><div class="p-num">1</div><div class="p-name">Commande & Paiement</div><div class="p-desc">Remplissez le formulaire et réglez 20 € via PayPal. Un numéro de commande est généré.</div></div>
                <div class="p-step"><div class="p-num">2</div><div class="p-name">Dépôt du document</div><div class="p-desc">Déposez votre PDF directement sur la page — aucun email à envoyer.</div></div>
                <div class="p-step"><div class="p-num">3</div><div class="p-name">Rapport sous 24h</div><div class="p-desc">Verdict clair + détail de chaque anomalie détectée. PDF conservable.</div></div>
            </div>
        </div>
    </section>

    <!-- EXPERTISE -->
    <section class="section" id="expert">
        <div class="s-label">// Preuve_Technique</div>
        <h2 class="s-title">Voici <span class="accent">exactement</span> ce que le rapport contient.</h2>
        <p class="s-desc">Pas de promesses vagues. Un exemple réel, sur un dossier détecté comme suspect :</p>
        <div class="report-section">
            <div class="r-head">Rapport d'audit BailSafe — Dossier_0042.pdf</div>
            <div class="r-rows">
                <div class="r-row"><span class="r-label">Statut global</span><span class="r-val v-red">SUSPECT — Anomalies majeures</span></div>
                <div class="r-row"><span class="r-label">Score de risque</span><span class="r-val v-red">94 / 100</span></div>
                <div class="r-row"><span class="r-label">Hash SHA-256</span><span class="r-val">a3f9c2d1... (vérifié)</span></div>
                <div class="r-row"><span class="r-label">Sections xref</span><span class="r-val v-orange">3 → structure remaniée</span></div>
                <div class="r-row"><span class="r-label">Logiciel détecté</span><span class="r-val v-red">Adobe Photoshop 2023</span></div>
                <div class="r-row"><span class="r-label">Écart budgétaire</span><span class="r-val v-red">1 240 € — seuil dépassé</span></div>
                <div class="r-row"><span class="r-label">JavaScript</span><span class="r-val v-green">Aucun</span></div>
                <div class="r-row"><span class="r-label">Recommandation</span><span class="r-val v-orange">Demander l'original ou refuser</span></div>
            </div>
        </div>
        <div class="author-box">
            <div class="author-avatar">NB</div>
            <div class="author-text"><strong>Nolan, créateur de BailSafe.</strong> J'ai construit cet outil après avoir constaté qu'un PDF de fiche de paie se falsifie en moins de 10 minutes avec des outils gratuits — et que les propriétaires n'avaient aucun moyen technique de le détecter. BailSafe automatise l'analyse que seul un expert pouvait réaliser avant.</div>
        </div>
    </section>

    <!-- FAQ -->
    <section class="section" id="faq">
        <div class="s-label">// Questions_Fréquentes</div>
        <h2 class="s-title">Ce que les bailleurs <span class="accent">demandent toujours.</span></h2>
        <p class="s-desc">Les vraies questions avant de commander un audit.</p>
        <div class="faq-section">
            <div class="faq-item">
                <div class="faq-q" onclick="toggleFaq(this)">Est-ce légal de refuser un locataire sur la base de ce rapport ?<span class="faq-icon">+</span></div>
                <div class="faq-a">Oui — à condition que le motif de refus soit lié à l'authenticité du document, et non à un critère discriminatoire. Le rapport BailSafe est un avis technique sur l'intégrité du fichier PDF. Si des anomalies forensiques sont détectées, vous êtes en droit de demander un document original ou une alternative. La décision finale vous appartient. En cas de doute, consultez un professionnel du droit.</div>
            </div>
            <div class="faq-item">
                <div class="faq-q" onclick="toggleFaq(this)">Que faire si le rapport dit "SUSPECT" ?<span class="faq-icon">+</span></div>
                <div class="faq-a">Trois options : (1) demander au candidat de fournir l'original imprimé ou un document émis directement par l'employeur/administration, (2) contacter l'employeur pour vérifier les informations via net-entreprises.fr, (3) refuser le dossier en motivant votre décision par un document incomplet ou non vérifiable. Un rapport "SUSPECT" n'est pas une condamnation — c'est un signal d'alerte qui vous protège.</div>
            </div>
            <div class="faq-item">
                <div class="faq-q" onclick="toggleFaq(this)">BailSafe peut-il se tromper ?<span class="faq-icon">+</span></div>
                <div class="faq-a">Oui, dans deux cas rares : un document imprimé puis re-scanné après modification n'a plus de métadonnées numériques (faux négatif possible), et certains logiciels légitimes de paie génèrent des PDF avec plusieurs sections xref sans fraude. C'est pourquoi le rapport est un avis consultatif, pas une preuve juridique.</div>
            </div>
            <div class="faq-item">
                <div class="faq-q" onclick="toggleFaq(this)">Combien de temps pour recevoir le rapport ?<span class="faq-icon">+</span></div>
                <div class="faq-a">Sous 24 heures ouvrées après dépôt du PDF et confirmation du paiement. En pratique, la majorité des rapports sont livrés dans la même journée.</div>
            </div>
            <div class="faq-item">
                <div class="faq-q" onclick="toggleFaq(this)">Mes données sont-elles en sécurité ?<span class="faq-icon">+</span></div>
                <div class="faq-a">Le PDF est analysé localement et supprimé sous 30 jours maximum. Aucune donnée n'est revendue ni partagée. BailSafe est conforme au RGPD. En tant que bailleur, vous êtes responsable d'informer votre candidat que son document fait l'objet d'une vérification technique.</div>
            </div>
        </div>
    </section>

    <!-- OFFER -->
    <section class="section" id="offer">
        <div class="s-label">// Offre_Finale</div>
        <h2 class="s-title">Un dossier frauduleux coûte des milliers.<br><span class="accent">L'audit en coûte 20 €.</span></h2>
        <p class="s-desc">Votre candidat semble sérieux. Peut-être qu'il l'est. Mais si son PDF a été retouché, vous ne le verrez jamais — BailSafe si.</p>
        <div class="offer-box">
            <div class="offer-head">
                <div class="offer-price">20 €</div>
                <div class="offer-unit">TTC par dossier analysé</div>
                <div class="offer-tag">RAPPORT PDF INCLUS · SOUS 24H</div>
            </div>
            <div class="offer-body">
                <div class="objections">
                    <div class="obj-item"><span class="obj-check">✓</span><span>Commande directe — pas de compte à créer, pas de logiciel.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Déposez votre PDF directement sur la page après paiement — aucun email à envoyer.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Le rapport est daté et conservable — utile en cas de litige.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Conforme RGPD — données supprimées sous 30 jours.</span></div>
                </div>
                <div class="offer-buttons">
                    <button class="btn-final" onclick="window.open('https://leboncoin.fr/profil/3780fc14-e927-43d6-b826-40c02a3300c2','_blank')">Commander mon audit — 20 € sur LeBonCoin</button>
                    <button class="btn-secondary-final" onclick="window.open('https://www.facebook.com/share/1KKBK1mfpV/?mibextid=wwXlfr','_blank')">Retrouver BailSafe sur Facebook</button>
                </div>
                <div class="form-divider">ou commander directement ici</div>

                <!-- FORMULAIRE -->
                <div id="form-section">
                    <div class="form-box">
                        <div class="form-box-title">📋 Commander via ce formulaire</div>
                        <div class="form-box-sub">Remplissez vos infos — un numéro de commande sera généré pour le suivi</div>
                        <div class="form-grid">
                            <div>
                                <label class="f-label">Prénom & Nom *</label>
                                <input class="f-input" type="text" id="name" required placeholder="Jean Dupont">
                            </div>
                            <div>
                                <label class="f-label">Email *</label>
                                <input class="f-input" type="email" id="email" required placeholder="vous@email.com">
                            </div>
                            <div>
                                <label class="f-label">Téléphone</label>
                                <input class="f-input" type="tel" id="phone" placeholder="+33 6 00 00 00 00">
                            </div>
                            <div>
                                <label class="f-label">Type de document *</label>
                                <select class="f-select" id="doctype" required>
                                    <option value="" disabled selected>Choisir...</option>
                                    <option value="Fiche de paie">Fiche de paie</option>
                                    <option value="Avis d'imposition">Avis d'imposition</option>
                                    <option value="Contrat de travail">Contrat de travail</option>
                                    <option value="Relevé bancaire">Relevé bancaire</option>
                                    <option value="Autre">Autre</option>
                                </select>
                            </div>
                            <div class="form-full">
                                <label class="f-label">Message / Précisions (optionnel)</label>
                                <textarea class="f-textarea" id="message" placeholder="Ex : dossier pour un T3 à 800€/mois..."></textarea>
                            </div>
                            <div class="form-full">
                                <div class="gdpr-checkbox">
                                    <input type="checkbox" id="gdpr" required>
                                    <label for="gdpr">J'accepte que mes données soient traitées par BailSafe pour le traitement de ma commande. J'ai pris connaissance de la <a href="#privacy">politique de confidentialité</a>. Données conservées 30 jours maximum.</label>
                                </div>
                            </div>
                            <div class="form-full">
                                <button type="button" class="btn-form-submit" id="submitBtn" onclick="handleSubmit()">
                                    <span id="submitText">📤 Envoyer ma demande</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- CONFIRMATION PAIEMENT -->
                <div class="payment-confirm" id="paymentConfirm">
                    <div class="pc-icon">✅</div>
                    <div class="pc-title">Demande enregistrée !</div>
                    <div class="pc-sub">Votre numéro de commande :</div>
                    <div class="num-commande-box">
                        <div class="num-commande-label">N° de commande</div>
                        <div id="numCommande">—</div>
                    </div>
                    <div class="pc-sub" style="margin-bottom:16px">Notez ce numéro. Réglez maintenant, puis <strong style="color:#f59e0b">faites défiler la page vers le bas</strong> pour déposer votre document.</div>
                    <button class="btn-paypal" onclick="window.open('{PAYPAL_LINK}','_blank')">
                        🅿️ Payer 20 € via PayPal
                    </button>
                    <div class="scroll-hint">
                        ⬇️ Après le paiement, revenez sur cette page et faites défiler vers le bas pour déposer votre PDF.
                    </div>
                    <div class="pc-note">Paiement 100% sécurisé · Remboursé si document incompatible</div>
                </div>

                <div class="garantie">✓ Si l'analyse ne peut pas être réalisée (document scanné ou illisible), vous êtes remboursé intégralement.</div>
            </div>
        </div>
    </section>

    <!-- POLITIQUE RGPD -->
    <section class="section" id="privacy">
        <div class="s-label">// Conformité_RGPD</div>
        <h2 class="s-title">Confidentialité & <span class="accent">mentions légales</span></h2>
        <div class="s-desc" style="max-width:760px">

            <p><strong>Éditeur du service</strong><br>
            Nolan Bunet — BailSafe, auto-entrepreneur, Sainte-Rose (97115), Guadeloupe.<br>
            SIRET : <em>en cours d'immatriculation</em>.<br>
            Contact : <a href="mailto:{CONTACT_EMAIL}" style="color:#f59e0b">{CONTACT_EMAIL}</a>.</p>

            <p style="margin-top:16px"><strong>Hébergement</strong><br>
            Ce service est hébergé par Streamlit Inc. (San Francisco, CA, USA) via Streamlit Community Cloud.
            Les fichiers transmis transitent par les serveurs Streamlit le temps de la session, puis sont supprimés.</p>

            <p style="margin-top:16px"><strong>Données collectées</strong><br>
            Via le formulaire de commande : nom, email, téléphone (optionnel), type de document.<br>
            Via l'espace de dépôt : le fichier PDF que vous transmettez volontairement pour analyse.</p>

            <p style="margin-top:16px"><strong>Finalité du traitement</strong><br>
            Traiter votre commande et réaliser l'analyse technique d'authenticité documentaire demandée.</p>

            <p style="margin-top:16px"><strong>Base légale (art. 6 RGPD)</strong><br>
            Exécution du contrat (art. 6.1.b) pour le traitement de votre commande.<br>
            Intérêt légitime du bailleur (art. 6.1.f) pour la vérification d'authenticité des pièces justificatives.</p>

            <p style="margin-top:16px"><strong>Documents de tiers — obligation d'information</strong><br>
            Si vous transmettez les documents d'un candidat locataire, vous avez l'obligation légale de l'en informer préalablement (art. 13 et 14 RGPD).
            BailSafe n'analyse que les documents légalement exigibles au sens du décret n°2015-1437 du 5 novembre 2015.</p>

            <p style="margin-top:16px"><strong>Aucune décision automatisée</strong><br>
            Le rapport BailSafe est un avis technique consultatif portant sur l'intégrité du document, non sur la personne.
            La décision d'accepter ou de refuser un dossier appartient exclusivement au bailleur (art. 22 RGPD).</p>

            <p style="margin-top:16px"><strong>Durée de conservation</strong><br>
            Documents PDF et données de commande supprimés sous 30 jours maximum à compter de la livraison du rapport.</p>

            <p style="margin-top:16px"><strong>Vos droits</strong><br>
            Conformément aux articles 15 à 21 du RGPD, vous disposez des droits suivants :<br>
            accès · rectification · effacement · opposition · limitation du traitement · portabilité.<br>
            Pour les exercer : <a href="mailto:{CONTACT_EMAIL}?subject=RGPD - Exercice de droits" style="color:#f59e0b">{CONTACT_EMAIL}</a>.
            Réponse garantie sous 1 mois (délai légal).<br>
            En cas de réclamation non traitée : <a href="https://www.cnil.fr" target="_blank" style="color:#f59e0b">cnil.fr</a>.</p>

        </div>
    </section>

    <!-- FOOTER -->
    <footer class="footer">
        <div class="footer-logo"><span class="fa-solid fa-shield-halved" style="color:#f59e0b;margin-right:6px"></span>Bail<span class="mark">Safe</span></div>
        <p>© 2026 BailSafe. L'analyse forensique est un outil d'aide à la décision — aucune décision automatisée n'est prise sur les personnes.</p>
        <div class="footer-links">
            <a href="#privacy">Politique de confidentialité</a>
            <span>·</span>
            <a href="mailto:{CONTACT_EMAIL}?subject=RGPD - Droit à l'oubli">Droit à l'oubli</a>
            <span>·</span>
            <a href="mailto:{CONTACT_EMAIL}">Contact</a>
        </div>
        <p style="margin-top:12px;font-size:11px;color:#64748b">{CONTACT_EMAIL} · Sainte-Rose, Guadeloupe</p>
    </footer>

    <div class="toast" id="toast"></div>

    <script>
        const FORMSPREE_URL = "{FORMSPREE_ENDPOINT}";

        function toggleMenu() {{
            document.getElementById('burger').classList.toggle('open');
            document.getElementById('mobileMenu').classList.toggle('open');
        }}
        function closeMenu() {{
            document.getElementById('burger').classList.remove('open');
            document.getElementById('mobileMenu').classList.remove('open');
        }}

        function toggleFaq(el) {{
            const item = el.parentElement;
            const wasOpen = item.classList.contains('open');
            document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('open'));
            if (!wasOpen) item.classList.add('open');
        }}

        function showToast(msg, isError = false) {{
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = 'toast' + (isError ? ' error' : '') + ' show';
            setTimeout(() => {{ t.className = 'toast' + (isError ? ' error' : ''); }}, 4000);
        }}

        function genererNumero() {{
            const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
            let code = '';
            for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
            return 'BS-' + new Date().getFullYear() + '-' + code;
        }}

        // Scanner animation
        setTimeout(() => {{
            const fill = document.getElementById('scorefill');
            const num  = document.getElementById('scorenum');
            const verd = document.getElementById('verd');
            if (!fill) return;
            fill.style.width = '94%';
            let t0 = null;
            function tick(ts) {{
                if (!t0) t0 = ts;
                const p = Math.min((ts - t0) / 2200, 1);
                const ease = 1 - Math.pow(1 - p, 4);
                num.textContent = Math.round(ease * 94) + '/100';
                if (p === 1) verd.style.opacity = '1';
                if (p < 1) requestAnimationFrame(tick);
            }}
            requestAnimationFrame(tick);
        }}, 900);

        async function handleSubmit() {{
            const name    = document.getElementById('name').value.trim();
            const email   = document.getElementById('email').value.trim();
            const phone   = document.getElementById('phone').value.trim();
            const doctype = document.getElementById('doctype').value;
            const message = document.getElementById('message').value.trim();
            const gdpr    = document.getElementById('gdpr').checked;

            if (!name || !email || !doctype) {{ showToast('⚠️ Remplis les champs obligatoires', true); return; }}
            if (!gdpr) {{ showToast('⚠️ Accepte la politique de confidentialité', true); return; }}

            const btn = document.getElementById('submitBtn');
            const txt = document.getElementById('submitText');
            btn.disabled = true;
            txt.textContent = '⏳ Envoi en cours...';

            const numero = genererNumero();

            try {{
                const res = await fetch(FORMSPREE_URL, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'Accept': 'application/json' }},
                    body: JSON.stringify({{
                        name, email,
                        phone: phone || 'Non renseigné',
                        document_type: doctype,
                        message: message || 'Aucune précision',
                        numero_commande: numero,
                        gdpr_consent: 'Accepté',
                        _subject: '🛡️ Commande BailSafe ' + numero + ' — ' + name,
                        _replyto: email
                    }})
                }});

                if (res.ok) {{
                    document.getElementById('numCommande').textContent = numero;
                    document.getElementById('form-section').style.display = 'none';
                    const confirm = document.getElementById('paymentConfirm');
                    confirm.classList.add('visible');
                    confirm.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    showToast('✅ Commande ' + numero + ' enregistrée !');
                }} else {{
                    throw new Error('Erreur ' + res.status);
                }}
            }} catch (err) {{
                btn.disabled = false;
                txt.textContent = '📤 Envoyer ma demande';
                showToast('❌ Erreur. Contacte bunetnolan@gmail.com', true);
            }}
        }}
    </script>
</body>
</html>
"""

# ─── RENDU HTML ────────────────────────────────────────────────────────────────
st.components.v1.html(html_content, height=5600, scrolling=True)

# ─── SECTION UPLOAD STREAMLIT (hors iframe, après paiement) ───────────────────
st.markdown("""
<div style="background:#0f172a;padding:56px 24px 48px;text-align:center;margin-top:-8px">
    <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#f59e0b;font-weight:700;margin-bottom:12px">// Étape 2 — Après paiement</div>
    <h2 style="font-size:1.8rem;font-weight:800;color:#fff;margin-bottom:12px">📎 Déposez votre document ici</h2>
    <p style="color:#94a3b8;font-size:15px;max-width:560px;margin:0 auto;line-height:1.7">
        Vous avez réglé le paiement ? Déposez votre PDF directement ci-dessous.<br>
        Votre rapport vous sera envoyé sous 24h à l'adresse email indiquée.
    </p>
</div>
""", unsafe_allow_html=True)

# Rappel paiement
st.markdown("""
<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);border-radius:8px;
            padding:14px 20px;margin:20px auto;max-width:600px;font-size:13px;color:#b45309;text-align:center">
    ⚠️ <strong>Déposez votre document uniquement après avoir effectué le paiement PayPal.</strong><br>
    Sans paiement confirmé, l'analyse ne sera pas traitée.
</div>
""", unsafe_allow_html=True)

_, col_center, _ = st.columns([1, 2, 1])
with col_center:
    if not st.session_state.document_envoye:
        email_input = st.text_input(
            "Votre email *",
            placeholder="vous@email.com",
            help="Le même que celui saisi dans le formulaire de commande"
        )
        pdf_file = st.file_uploader(
            "Votre document PDF *",
            type=["pdf"],
            help="Fiche de paie, avis d'imposition, contrat de travail, relevé bancaire — Max 10 Mo"
        )

        # Validation en temps réel
        erreurs = []
        if email_input and not email_valide(email_input):
            erreurs.append("⚠️ Adresse email invalide.")
        if pdf_file and pdf_file.size > MAX_PDF_BYTES:
            erreurs.append(f"⚠️ Fichier trop lourd ({pdf_file.size//1024//1024} Mo). Maximum 10 Mo.")

        for err in erreurs:
            st.warning(err)

        pret = pdf_file and email_input and email_valide(email_input) and (not pdf_file or pdf_file.size <= MAX_PDF_BYTES)

        if pret:
            if st.button("📤 Envoyer le document à BailSafe", type="primary", use_container_width=True):
                pdf_bytes = pdf_file.read()  # lu une seule fois, immédiatement
                with st.spinner("Envoi sécurisé en cours..."):
                    ok, msg_retour = envoyer_document(
                        pdf_bytes=pdf_bytes,
                        filename=pdf_file.name,
                        client_email=email_input.strip()
                    )
                if ok:
                    st.session_state.document_envoye = True
                    st.rerun()
                else:
                    st.error(f"Erreur d'envoi : {msg_retour}  \nContactez directement : bunetnolan@gmail.com")
        elif email_input or pdf_file:
            st.info("Remplis tous les champs correctement pour envoyer le document.")

    else:
        st.markdown("""
<div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:10px;
            padding:28px 24px;text-align:center;margin:8px 0">
    <div style="font-size:36px;margin-bottom:12px">✅</div>
    <div style="font-size:18px;font-weight:800;color:#065f46;margin-bottom:8px">Document reçu !</div>
    <div style="font-size:14px;color:#047857;line-height:1.7">
        Votre rapport BailSafe vous sera envoyé <strong>sous 24h</strong> à l'adresse email indiquée.<br>
        Conservez votre email de confirmation comme référence.
    </div>
</div>
""", unsafe_allow_html=True)
        if st.button("Déposer un autre document", use_container_width=True):
            st.session_state.document_envoye = False
            st.rerun()

st.markdown("""
<p style="text-align:center;font-size:12px;color:#94a3b8;padding:20px 0 40px">
    🔒 Transmis via connexion sécurisée TLS · Supprimé sous 30 jours · Conforme RGPD
</p>
""", unsafe_allow_html=True)
