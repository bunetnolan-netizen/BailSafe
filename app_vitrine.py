import streamlit as st

st.set_page_config(
    page_title="BailSafe | Détection de Fraude Locative par IA",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

html_content = """
<!DOCTYPE html>
<html lang="fr" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BailSafe | Détection de Fraude Locative par IA</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
        .smooth { scroll-behavior: smooth; }

        nav { position: fixed; top: 0; width: 100%; z-index: 50; background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .nav-inner { max-width: 1400px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; height: 64px; }
        .logo { display: flex; align-items: center; gap: 8px; color: white; font-weight: bold; font-size: 20px; text-decoration: none; }
        .logo .shield { color: #f59e0b; font-size: 24px; }
        .logo .mark { color: #f59e0b; }
        .nav-links { display: none; gap: 32px; }
        .nav-links a { color: #cbd5e1; text-decoration: none; font-size: 14px; font-weight: 500; transition: color 0.2s; }
        .nav-links a:hover { color: #fff; }
        @media (min-width: 768px) { .nav-links { display: flex; } }
        .nav-cta { background: #f59e0b; color: #1e293b; padding: 10px 20px; border-radius: 6px; font-weight: 700; font-size: 13px; border: none; cursor: pointer; transition: background 0.2s; }
        .nav-cta:hover { background: #fbbf24; }

        .hero { background: #0f172a; padding: 120px 24px 80px; text-align: center; position: relative; overflow: hidden; }
        .hero::before { content: ''; position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 1000px; height: 500px; background: radial-gradient(ellipse, rgba(245, 158, 11, 0.15), transparent 70%); pointer-events: none; }
        .hero-content { max-width: 800px; margin: 0 auto; position: relative; z-index: 1; }
        .h-badge { display: inline-block; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: #fbbf24; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; letter-spacing: 1px; margin-bottom: 24px; text-transform: uppercase; }
        .h-title { font-size: clamp(2rem, 6vw, 3.5rem); font-weight: 800; color: #fff; margin-bottom: 20px; line-height: 1.15; }
        .h-title .accent { background: linear-gradient(135deg, #f59e0b, #ff6b6b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .h-sub { font-size: 1.15rem; color: #cbd5e1; max-width: 650px; margin: 0 auto 32px; line-height: 1.7; }
        .h-buttons { display: flex; flex-direction: column; gap: 12px; justify-content: center; margin-bottom: 20px; }
        .h-buttons button { font-size: 16px; }
        @media (min-width: 640px) { .h-buttons { flex-direction: row; } }
        .btn-primary { background: #f59e0b; color: #1e293b; padding: 14px 28px; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.25); }
        .btn-primary:hover { background: #fbbf24; transform: translateY(-2px); box-shadow: 0 8px 20px rgba(245, 158, 11, 0.35); }
        .btn-secondary { background: transparent; color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); padding: 14px 28px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-secondary:hover { border-color: rgba(245, 158, 11, 0.7); background: rgba(245, 158, 11, 0.05); }
        .h-proof { display: flex; gap: 30px; justify-content: center; flex-wrap: wrap; font-size: 13px; color: #94a3b8; }
        .h-proof span { color: #f59e0b; }

        .scanner-demo { max-width: 800px; margin: 0 auto 0; padding: 0 24px; }
        .scan-container { background: #fff; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.12); overflow: hidden; border: 1px solid #e2e8f0; }
        @keyframes scanline { 0% { top: 0; opacity: 0; } 10% { opacity: 1; } 90% { opacity: 1; } 100% { top: 100%; opacity: 0; } }
        .scan-header { background: #f1f5f9; padding: 16px 24px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 12px; }
        .scan-dots { display: flex; gap: 8px; }
        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot-r { background: #ef4444; } .dot-y { background: #f59e0b; } .dot-g { background: #10b981; }
        .scan-name { font-size: 12px; color: #64748b; font-weight: 600; margin-left: 8px; }
        .scan-body { padding: 24px; position: relative; min-height: 280px; background: #fff; }
        .scan-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
        .scan-row:last-child { border-bottom: none; }
        .scan-label { color: #64748b; font-weight: 500; }
        .scan-val { color: #1e293b; font-weight: 600; }
        .badge-ok { background: #ecfdf5; color: #065f46; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .badge-alert { background: #fef2f2; color: #991b1b; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .badge-warn { background: #fef3c7; color: #92400e; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .scan-score { margin-top: 20px; padding-top: 20px; border-top: 1px solid #f1f5f9; }
        .score-label { display: flex; justify-content: space-between; font-size: 12px; color: #64748b; margin-bottom: 8px; }
        .score-num { font-size: 24px; font-weight: 800; color: #ef4444; }
        .score-bar { height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; }
        .score-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #f59e0b, #ef4444); border-radius: 3px; transition: width 2.2s cubic-bezier(0.16, 1, 0.3, 1); }
        .verdict { margin-top: 16px; padding: 12px 16px; background: #fef2f2; border-left: 3px solid #ef4444; color: #7f1d1d; font-size: 12px; border-radius: 4px; opacity: 0; transition: opacity 0.4s; font-weight: 600; }
        .scanner-line { position: absolute; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, transparent, #ef4444, transparent); box-shadow: 0 0 8px #ef4444; animation: scanline 2.8s ease-in-out infinite; z-index: 10; }

        .section { padding: 80px 24px; max-width: 1400px; margin: 0 auto; }
        .s-label { font-size: 12px; letter-spacing: 2px; text-transform: uppercase; color: #f59e0b; font-weight: 700; margin-bottom: 16px; }
        .s-title { font-size: clamp(2rem, 5vw, 3rem); font-weight: 800; color: #0f172a; margin-bottom: 16px; line-height: 1.2; }
        .s-title .accent { color: #f59e0b; }
        .s-desc { font-size: 1.05rem; color: #475569; max-width: 700px; line-height: 1.8; margin-bottom: 32px; }

        .pain-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 32px; }
        .pain-card { background: #fff; border: 1px solid #e2e8f0; border-left: 4px solid #ef4444; border-radius: 8px; padding: 24px; transition: all 0.2s; }
        .pain-card:hover { transform: translateY(-4px); box-shadow: 0 12px 24px rgba(0,0,0,0.08); }
        .pain-num { font-size: 28px; font-weight: 800; color: #f59e0b; margin-bottom: 8px; }
        .pain-title { font-weight: 700; color: #0f172a; margin-bottom: 8px; font-size: 15px; }
        .pain-desc { font-size: 14px; color: #64748b; line-height: 1.6; }

        .benefits-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 32px; }
        .benefit-card { background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; text-align: center; transition: all 0.2s; }
        .benefit-card:hover { border-color: #f59e0b; background: #fffbf0; }
        .b-icon { font-size: 28px; margin-bottom: 12px; }
        .b-title { font-weight: 700; color: #0f172a; margin-bottom: 8px; font-size: 15px; }
        .b-desc { font-size: 13px; color: #64748b; line-height: 1.6; }

        .process { margin-top: 48px; background: #f9fafb; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
        .process-head { background: #0f172a; color: #fff; padding: 16px 24px; font-size: 12px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }
        .process-steps { padding: 32px 24px; display: flex; flex-direction: column; gap: 24px; }
        @media (min-width: 768px) { .process-steps { flex-direction: row; justify-content: space-around; } }
        .p-step { display: flex; flex-direction: column; align-items: center; text-align: center; }
        .p-num { width: 40px; height: 40px; background: #f59e0b; color: #1e293b; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 800; margin-bottom: 12px; font-size: 18px; }
        .p-name { font-weight: 700; color: #0f172a; margin-bottom: 6px; font-size: 15px; }
        .p-desc { font-size: 13px; color: #64748b; line-height: 1.6; }

        .report-section { background: #f9fafb; border-radius: 8px; padding: 24px; margin-top: 32px; border: 1px solid #e2e8f0; }
        .r-head { font-size: 12px; color: #64748b; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 16px; }
        .r-rows { display: flex; flex-direction: column; gap: 12px; }
        .r-row { display: grid; grid-template-columns: 1fr auto; gap: 16px; font-size: 13px; padding: 8px 0; }
        .r-label { color: #64748b; }
        .r-val { font-weight: 700; color: #1e293b; font-family: 'Courier New', monospace; }
        .v-red { color: #dc2626; } .v-orange { color: #d97706; } .v-green { color: #16a34a; }

        .author-box { background: #fffbf0; border: 1px solid #fed7aa; border-radius: 8px; padding: 20px; margin-top: 24px; display: flex; gap: 16px; }
        .author-avatar { width: 48px; height: 48px; background: #f59e0b; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 16px; flex-shrink: 0; }
        .author-text { font-size: 14px; color: #78350f; line-height: 1.6; }
        .author-text strong { color: #b45309; }

        .offer-box { background: #0f172a; border-radius: 12px; overflow: hidden; margin-top: 32px; border: 1px solid rgba(245, 158, 11, 0.2); }
        .offer-head { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 32px 24px; text-align: center; }
        .offer-price { font-size: 3.5rem; font-weight: 800; color: #fff; margin-bottom: 4px; }
        .offer-unit { font-size: 14px; color: #cbd5e1; }
        .offer-tag { display: inline-block; background: rgba(245, 158, 11, 0.15); color: #fbbf24; padding: 6px 16px; border-radius: 6px; font-size: 12px; font-weight: 700; margin-top: 12px; border: 1px solid rgba(245, 158, 11, 0.3); }
        .offer-body { padding: 32px 24px; }
        .objections { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
        .obj-item { display: flex; gap: 12px; font-size: 14px; color: #cbd5e1; align-items: flex-start; }
        .obj-check { color: #10b981; font-weight: 800; font-size: 18px; flex-shrink: 0; margin-top: -2px; }
        .offer-buttons { display: flex; flex-direction: column; gap: 12px; }
        .btn-final { background: #f59e0b; color: #1e293b; padding: 16px; border: none; border-radius: 8px; font-weight: 800; font-size: 15px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.25); }
        .btn-final:hover { background: #fbbf24; transform: translateY(-2px); box-shadow: 0 8px 20px rgba(245, 158, 11, 0.35); }
        .btn-secondary-final { background: transparent; color: #cbd5e1; border: 1px solid rgba(245, 158, 11, 0.3); padding: 14px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-secondary-final:hover { border-color: rgba(245, 158, 11, 0.6); color: #fff; }
        .garantie { background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px; padding: 14px; font-size: 12px; color: #047857; margin-top: 16px; line-height: 1.6; }

        /* ── FORMULAIRE ── */
        .form-divider {
            display: flex; align-items: center; gap: 16px;
            margin: 28px 0; color: #94a3b8; font-size: 13px;
        }
        .form-divider::before, .form-divider::after {
            content: ''; flex: 1;
            height: 1px; background: rgba(148,163,184,0.2);
        }

        .form-box {
            background: #1e293b;
            border: 1px solid rgba(245,158,11,0.25);
            border-radius: 10px;
            padding: 28px 24px;
            margin-top: 0;
        }

        .form-box-title {
            font-size: 15px; font-weight: 700;
            color: #fff; margin-bottom: 6px;
            display: flex; align-items: center; gap: 8px;
        }
        .form-box-sub {
            font-size: 13px; color: #94a3b8; margin-bottom: 20px;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
        }
        @media (max-width: 600px) { .form-grid { grid-template-columns: 1fr; } }

        .form-full { grid-column: 1 / -1; }

        .f-label {
            display: block; font-size: 12px; font-weight: 600;
            color: #94a3b8; margin-bottom: 6px; letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .f-input, .f-select, .f-textarea {
            width: 100%; background: #0f172a;
            border: 1px solid rgba(148,163,184,0.2);
            border-radius: 6px; padding: 11px 14px;
            color: #fff; font-size: 14px; font-family: 'Inter', sans-serif;
            transition: border-color 0.2s;
            outline: none;
        }
        .f-input:focus, .f-select:focus, .f-textarea:focus {
            border-color: rgba(245,158,11,0.6);
        }
        .f-input::placeholder, .f-textarea::placeholder { color: #475569; }
        .f-select option { background: #1e293b; }
        .f-textarea { resize: vertical; min-height: 90px; }

        .btn-form-submit {
            width: 100%; background: #f59e0b; color: #1e293b;
            padding: 15px; border: none; border-radius: 8px;
            font-weight: 800; font-size: 15px; cursor: pointer;
            transition: all 0.2s; margin-top: 6px;
            box-shadow: 0 4px 12px rgba(245,158,11,0.25);
            display: flex; align-items: center; justify-content: center; gap: 8px;
        }
        .btn-form-submit:hover:not(:disabled) {
            background: #fbbf24; transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(245,158,11,0.35);
        }
        .btn-form-submit:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }

        /* Confirmation paiement */
        .payment-confirm {
            display: none;
            background: #0f172a;
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 10px;
            padding: 32px 24px;
            text-align: center;
        }
        .payment-confirm.visible { display: block; }
        .pc-icon { font-size: 40px; margin-bottom: 16px; }
        .pc-title { font-size: 20px; font-weight: 800; color: #fff; margin-bottom: 8px; }
        .pc-sub { font-size: 14px; color: #94a3b8; margin-bottom: 28px; line-height: 1.7; }
        .pc-buttons { display: flex; flex-direction: column; gap: 12px; }
        @media (min-width: 480px) { .pc-buttons { flex-direction: row; } }

        .btn-stripe {
            flex: 1; background: #635bff; color: #fff;
            padding: 14px 20px; border: none; border-radius: 8px;
            font-weight: 700; font-size: 14px; cursor: pointer;
            transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px;
        }
        .btn-stripe:hover { background: #7c75ff; transform: translateY(-2px); }

        .btn-paypal {
            flex: 1; background: #003087; color: #fff;
            padding: 14px 20px; border: none; border-radius: 8px;
            font-weight: 700; font-size: 14px; cursor: pointer;
            transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px;
        }
        .btn-paypal:hover { background: #00409a; transform: translateY(-2px); }

        .pc-note { font-size: 12px; color: #64748b; margin-top: 16px; }

        /* Toast */
        .toast {
            position: fixed; bottom: 24px; right: 24px;
            background: #1e293b; border: 1px solid rgba(245,158,11,0.4);
            color: #fff; padding: 14px 20px; border-radius: 8px;
            font-size: 13px; font-weight: 600; z-index: 9999;
            transform: translateY(80px); opacity: 0;
            transition: all 0.35s cubic-bezier(0.16,1,0.3,1);
            max-width: 320px;
        }
        .toast.show { transform: translateY(0); opacity: 1; }
        .toast.error { border-color: rgba(239,68,68,0.5); }

        .footer { background: #0f172a; color: #94a3b8; padding: 32px 24px; text-align: center; border-top: 1px solid rgba(148,163,184,0.1); font-size: 13px; }
        .footer-logo { color: #fff; font-weight: 700; margin-bottom: 8px; }
        .footer-logo .mark { color: #f59e0b; }
    </style>
</head>

<body class="smooth">

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
                <a href="#offer">Tarif</a>
            </div>
            <button class="nav-cta" onclick="document.getElementById('offer').scrollIntoView({behavior:'smooth'})">Sécuriser un dossier</button>
        </div>
    </nav>

    <!-- HERO -->
    <section class="hero">
        <div class="hero-content">
            <div class="h-badge">Service exclusif pour propriétaires bailleurs</div>
            <h1 class="h-title">Ne donnez pas les clés de votre bien à un <span class="accent">fraudeur</span> (sans le savoir).</h1>
            <p class="h-sub">Les fausses fiches de paie et avis d'imposition falsifiés sont devenues indétectables à l'œil nu. BailSafe détecte ces fraudes grâce à l'IA — évitez jusqu'à 3 ans de procédure d'expulsion et des milliers d'euros de pertes.</p>
            <div class="h-buttons">
                <button class="btn-primary" onclick="document.getElementById('offer').scrollIntoView({behavior:'smooth'})">Analyser un dossier maintenant (20€)</button>
                <button class="btn-secondary">Voir un exemple de rapport</button>
            </div>
            <div class="h-proof">
                <div><span>⚡ Résultat rapide</span></div>
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
                    <div class="dot dot-r"></div>
                    <div class="dot dot-y"></div>
                    <div class="dot dot-g"></div>
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
                    <div class="score-label">
                        <span>Score de risque</span>
                        <span class="score-num" id="scorenum">0</span>
                    </div>
                    <div class="score-bar"><div class="score-fill" id="scorefill"></div></div>
                    <div class="verdict" id="verd">⚠️ VERDICT: SUSPECT — Falsification probable. Refuser ou demander l'original.</div>
                </div>
                <div class="scanner-line"></div>
            </div>
        </div>
    </div>

    <!-- PAIN POINTS -->
    <section class="section" id="pain">
        <div class="s-label">// Le_Problème</div>
        <h2 class="s-title">Vous contrôlez à l'œil nu. <span class="accent">Les fraudeurs le savent.</span></h2>
        <p class="s-desc">Les fausses fiches de paie, avis d'imposition modifiés et contrats bidons ne se voient plus. Ils sont générés en PDF propre, avec des outils gratuits accessibles à tous.</p>
        <div class="pain-grid">
            <div class="pain-card">
                <div class="pain-num">01</div>
                <div class="pain-title">Un impayé = ~3 000 € de pertes minimum</div>
                <div class="pain-desc">Avant toute procédure légale. Sans compter les mois de vacance locative et les frais d'huissier.</div>
            </div>
            <div class="pain-card">
                <div class="pain-num">02</div>
                <div class="pain-title">Un montant modifié est invisible à l'œil nu</div>
                <div class="pain-desc">Le chiffre semble juste, la mise en page aussi. Seule une analyse forensique trahit la manipulation.</div>
            </div>
            <div class="pain-card">
                <div class="pain-num">03</div>
                <div class="pain-title">Une fois le bail signé, vous êtes bloqué</div>
                <div class="pain-desc">L'expulsion prend 12 à 18 mois. Un dossier non vérifié vous coûtera bien plus que 20 €.</div>
            </div>
            <div class="pain-card">
                <div class="pain-num">04</div>
                <div class="pain-title">Faire confiance à son instinct = roulette</div>
                <div class="pain-desc">Les fraudeurs sont polis, bien préparés, et suivent des tutoriels pour falsifier leurs documents.</div>
            </div>
        </div>
    </section>

    <!-- BENEFITS -->
    <section class="section" id="benefits">
        <div class="s-label">// La_Solution</div>
        <h2 class="s-title">Ce que BailSafe analyse <span class="accent">en moins de 24h.</span></h2>
        <p class="s-desc">Pas de formulaire compliqué, pas de spécialiste à convaincre. Vous envoyez le PDF — BailSafe inspecte la structure profonde et vous livre un verdict clair.</p>
        <div class="benefits-grid">
            <div class="benefit-card"><div class="b-icon">🔬</div><div class="b-title">Forensique métadonnées</div><div class="b-desc">Détecte Photoshop, Canva et outils d'édition cachés dans la structure du PDF.</div></div>
            <div class="benefit-card"><div class="b-icon">🔐</div><div class="b-title">Intégrité SHA-256</div><div class="b-desc">Empreinte unique — prouve que le document n'a pas été altéré après émission.</div></div>
            <div class="benefit-card"><div class="b-icon">💰</div><div class="b-title">Cohérence budgétaire</div><div class="b-desc">Vérifie automatiquement si les cumuls de salaire correspondent aux mensualités.</div></div>
            <div class="benefit-card"><div class="b-icon">📄</div><div class="b-title">Rapport PDF transmissible</div><div class="b-desc">Document daté, conservable, utile en cas de litige ou refus motivé.</div></div>
        </div>
        <div class="process">
            <div class="process-head">Procédure — 3 Étapes</div>
            <div class="process-steps">
                <div class="p-step"><div class="p-num">1</div><div class="p-name">Commande LeBonCoin</div><div class="p-desc">Paiement sécurisé. Vous envoyez le PDF par email.</div></div>
                <div class="p-step"><div class="p-num">2</div><div class="p-name">Analyse complète</div><div class="p-desc">Structure PDF, métadonnées, finances, intégrité.</div></div>
                <div class="p-step"><div class="p-num">3</div><div class="p-name">Rapport sous 24h</div><div class="p-desc">Verdict clair + détail de chaque anomalie détectée.</div></div>
            </div>
        </div>
    </section>

    <!-- EXPERTISE -->
    <section class="section" id="expert">
        <div class="s-label">// Preuve_Technique</div>
        <h2 class="s-title">Voici <span class="accent">exactement</span> ce que le rapport contient.</h2>
        <p class="s-desc">Pas de promesses vagues. Un exemple réel, sur un dossier détecté comme suspect :</p>
        <div class="report-section">
            <div class="r-head">Rapport d'audit bailsafe — Dossier_0042.pdf</div>
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
                    <div class="obj-item"><span class="obj-check">✓</span><span>Commande directe sur LeBonCoin — pas de compte à créer, pas de logiciel.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Vous envoyez juste le PDF par email — aucune manipulation technique requise.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Le rapport est daté et conservable — utile en cas de litige ou refus motivé.</span></div>
                    <div class="obj-item"><span class="obj-check">✓</span><span>Analyse en mémoire uniquement — aucune donnée stockée, conforme RGPD.</span></div>
                </div>

                <div class="offer-buttons">
                    <button class="btn-final" onclick="window.open('https://leboncoin.fr/profil/3780fc14-e927-43d6-b826-40c02a3300c2','_blank')">Commander mon audit — 20 € sur LeBonCoin</button>
                    <button class="btn-secondary-final" onclick="window.open('https://www.facebook.com/share/1KKBK1mfpV/?mibextid=wwXlfr','_blank')">Retrouver BailSafe sur Facebook</button>
                </div>

                <!-- SÉPARATEUR -->
                <div class="form-divider">ou commander directement ici</div>

                <!-- FORMULAIRE -->
                <div id="form-section">
                    <div class="form-box">
                        <div class="form-box-title">
                            📋 Commander via ce formulaire
                        </div>
                        <div class="form-box-sub">Remplissez vos informations — vous serez redirigé vers le paiement sécurisé (Stripe ou PayPal) après envoi.</div>

                        <div class="form-grid">
                            <div>
                                <label class="f-label">Prénom & Nom *</label>
                                <input class="f-input" type="text" id="f_name" placeholder="Jean Dupont" required>
                            </div>
                            <div>
                                <label class="f-label">Email *</label>
                                <input class="f-input" type="email" id="f_email" placeholder="vous@email.com" required>
                            </div>
                            <div>
                                <label class="f-label">Téléphone</label>
                                <input class="f-input" type="tel" id="f_phone" placeholder="+33 6 00 00 00 00">
                            </div>
                            <div>
                                <label class="f-label">Type de document à analyser *</label>
                                <select class="f-select" id="f_doctype">
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
                                <textarea class="f-textarea" id="f_message" placeholder="Ex : dossier pour un T3 à 800€/mois, candidat auto-entrepreneur..."></textarea>
                            </div>
                            <div class="form-full">
                                <button class="btn-form-submit" id="submitBtn" onclick="handleFormSubmit()">
                                    <span id="submitText">📤 Envoyer ma demande et payer</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- CONFIRMATION + CHOIX PAIEMENT -->
                <div class="payment-confirm" id="paymentConfirm">
                    <div class="pc-icon">✅</div>
                    <div class="pc-title">Demande reçue !</div>
                    <div class="pc-sub">Votre demande a bien été envoyée. Finalisez maintenant votre paiement de <strong style="color:#f59e0b">20 €</strong> pour lancer l'analyse. Vous recevrez le rapport sous 24h à l'adresse indiquée.</div>
                    <div class="pc-buttons">
                        <button class="btn-stripe" onclick="window.open('https://buy.stripe.com/test_3cI14ngjC4aga5L0fL0RG00','_blank')">
                            💳 Payer par carte (Stripe)
                        </button>
                        <button class="btn-paypal" onclick="window.open('paypal.me/NolanBunet/20EUR','_blank')">
                            🅿️ Payer via PayPal
                        </button>
                    </div>
                    <div class="pc-note">Paiement 100% sécurisé · Remboursé si document incompatible</div>
                </div>

                <div class="garantie">✓ Si l'analyse ne peut pas être réalisée (scan papier, format incompatible), vous êtes remboursé intégralement — sans questions.</div>
            </div>
        </div>
    </section>

    <!-- FOOTER -->
    <footer class="footer">
        <div class="footer-logo">
            <span class="fa-solid fa-shield-halved" style="color:#f59e0b;margin-right:6px"></span>Bail<span class="mark">Safe</span>
        </div>
        <p>© 2026 BailSafe. La détection par IA est un outil d'aide à la décision. Le propriétaire reste le seul décideur final.</p>
        <p style="margin-top:8px;font-size:11px;color:#64748b">bunetnolan@icloud.com</p>
    </footer>

    <!-- TOAST -->
    <div class="toast" id="toast"></div>

    <script>
        // ── EmailJS init ──────────────────────────────────────────────
        // ⚠️  REMPLACE ces 3 valeurs par tes vraies clés EmailJS
        var EMAILJS_PUBLIC_KEY  = 'pIYqblvWNyPFoU8L8';   // Account > API Keys
        var EMAILJS_SERVICE_ID  = 'service_6e28n05';   // Email Services
        var EMAILJS_TEMPLATE_ID = 'template_6rbeve8';  // Email Templates

        emailjs.init(EMAILJS_PUBLIC_KEY);

        // ── Scanner animation ─────────────────────────────────────────
        setTimeout(function() {
            var fill = document.getElementById('scorefill');
            var num  = document.getElementById('scorenum');
            var verd = document.getElementById('verd');
            if (!fill) return;
            fill.style.width = '94%';
            var t0 = null;
            function tick(ts) {
                if (!t0) t0 = ts;
                var p    = Math.min((ts - t0) / 2200, 1);
                var ease = 1 - Math.pow(1 - p, 4);
                num.textContent = Math.round(ease * 94) + '/100';
                if (p === 1) verd.style.opacity = '1';
                if (p < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        }, 900);

        // ── Toast helper ──────────────────────────────────────────────
        function showToast(msg, isError) {
            var t = document.getElementById('toast');
            t.textContent = msg;
            t.className = 'toast' + (isError ? ' error' : '') + ' show';
            setTimeout(function() { t.className = 'toast' + (isError ? ' error' : ''); }, 4000);
        }
        emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, { ... })
        .then(function() {
           // ← ajoute ça : envoi auto-reply au client
         return emailjs.send(EMAILJS_SERVICE_ID, 'template_t4ep7ax', {
            from_name   : name,
            from_email  : email,
            doc_type    : doctype,
            reply_to    : email
                });
            })
       .then(function() {
           // affichage confirmation paiement (code existant)
                document.getElementById('form-section').style.display = 'none';
             ...
          })

        // ── Form submit ───────────────────────────────────────────────
        function handleFormSubmit() {
            var name    = document.getElementById('f_name').value.trim();
            var email   = document.getElementById('f_email').value.trim();
            var phone   = document.getElementById('f_phone').value.trim();
            var doctype = document.getElementById('f_doctype').value;
            var message = document.getElementById('f_message').value.trim();
            var btn     = document.getElementById('submitBtn');
            var txt     = document.getElementById('submitText');

            // Validation basique
            if (!name || !email || !doctype) {
                showToast('⚠️ Merci de remplir les champs obligatoires.', true);
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                showToast('⚠️ Adresse email invalide.', true);
                return;
            }

            btn.disabled = true;
            txt.textContent = '⏳ Envoi en cours...';

            var templateParams = {
                from_name   : name,
                from_email  : email,
                from_phone  : phone || 'Non renseigné',
                doc_type    : doctype,
                user_message: message || 'Aucune précision',
                reply_to    : email
            };

            emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, templateParams)
                .then(function() {
                    // Succès : masquer formulaire, afficher confirmation paiement
                    document.getElementById('form-section').style.display = 'none';
                    var confirm = document.getElementById('paymentConfirm');
                    confirm.classList.add('visible');
                    confirm.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    showToast('✅ Demande envoyée ! Choisissez votre mode de paiement.');
                })
                .catch(function(err) {
                    btn.disabled = false;
                    txt.textContent = '📤 Envoyer ma demande et payer';
                    showToast('❌ Erreur d\'envoi. Réessaie ou contacte bunetnolan@icloud.com', true);
                    console.error('EmailJS error:', err);
                });
        }
    </script>

</body>
</html>
"""

st.components.v1.html(html_content, height=1200, scrolling=True)
