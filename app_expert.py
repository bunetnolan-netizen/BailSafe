from __future__ import annotations

import streamlit as st

from app_vitrine import (
    AppSecrets,
    MathResult,
    analyser_forensic,
    analyser_math,
    calculer_verdict,
    construire_math_result,
    build_report_pdf,
    get_report_filename,
    envoyer_rapport,
    extract_pdf_content,
    is_valid_email,
)


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


def afficher_interface_expert() -> None:
    """Interface principale d'analyse expert."""
    
    # En-tête
    st.markdown("""
    <div style="background:linear-gradient(140deg,#0f172a,#1e3a8a);border:1px solid #f59e0b;
                border-radius:14px;padding:20px 24px;margin-bottom:24px">
        <h2 style="color:#fff;margin:0 0 4px">🕵️ Cockpit d'Analyse Expert</h2>
        <p style="color:#94a3b8;margin:0;font-size:.9rem">
            Forensique PDF avancée · Cohérence financière · Rapport PDF professionnel
        </p>
    </div>
    """, unsafe_allow_html=True)

    secrets = get_secrets()

    # Section paiement (optionnel)
    with st.expander("💰 Modèle de message client"):
        st.code(
            "Bonjour,\n\n"
            "Afin de lancer l'audit technique de votre dossier, merci de régler les 20 € "
            "d'honoraires via PayPal : paypal.me/NolanBunet/20EUR\n\n"
            "Dès réception du paiement, j'analyse les pièces et vous envoie le rapport PDF sous 24h.\n\n"
            "Cordialement,\nNolan — BailSafe",
            language="text",
        )

    # Upload PDF
    fichier_pdf = st.file_uploader("📂 Déposez le PDF à auditer", type="pdf")

    if fichier_pdf is None:
        st.info("📌 Déposez un fichier PDF pour démarrer l'analyse complète.")
        return

    # Gestion du cache d'analyse
    if "current_pdf_name" not in st.session_state or st.session_state["current_pdf_name"] != fichier_pdf.name:
        with st.spinner("🔍 Extraction et analyse du document en cours…"):
            st.session_state["analysis"] = extract_pdf_content(fichier_pdf)
            st.session_state["current_pdf_name"] = fichier_pdf.name
            st.session_state.pop("forensic_result", None)

    analysis = st.session_state["analysis"]

    if analysis.error:
        st.warning(f"⚠️ Lecture partielle : {analysis.error}")

    # Calcul forensique (lourd)
    if "forensic_result" not in st.session_state:
        st.session_state["forensic_result"] = analyser_forensic(analysis)
    
    forensic = st.session_state["forensic_result"]

    # Onglets d'analyse
    tab1, tab2, tab3 = st.tabs([
        "📊 Cohérence financière",
        "🔎 Forensique PDF",
        "📤 Verdict & Rapport",
    ])

    # ========== TAB 1 : MATH ==========
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

    # ========== TAB 2 : FORENSIQUE ==========
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

    # ========== TAB 3 : VERDICT ==========
    with tab3:
        st.subheader("Verdict global et rapport")
        
        math_r = st.session_state.get("math_result")
        forensic_r = st.session_state.get("forensic_result")

        if math_r is None or forensic_r is None:
            st.warning("⚠️ Veuillez d'abord consulter les onglets précédents.")
            return

        verdict = calculer_verdict(math_r, forensic_r)

        # Affichage du verdict
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

        st.markdown("#### Recommandations")
        
        if verdict.score_risque >= 80:
            recs = [
                "🔴 **Bloquer la validation** — Demander l'original signé du document",
                "🔴 **Exiger une vérification supplémentaire** (appel à l'employeur, etc.)",
                "🔴 **Conserver ce rapport** dans le dossier candidat",
            ]
            st.error("Ce dossier présente des signaux d'alerte importants")
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

        # Génération du rapport PDF
        pdf_bytes = build_report_pdf(verdict, forensic_r)
        filename = get_report_filename(verdict.statut)

        st.markdown("#### Transmission du rapport")
        
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
        page_icon="🕵️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Styling global
    st.markdown("""
    <style>
    [data-testid="stMetricValue"] { font-size: 28px; }
    [data-testid="stMetricDelta"] { font-size: 14px; }
    </style>
    """, unsafe_allow_html=True)
    
    afficher_interface_expert()


if __name__ == "__main__":
    main()
