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
    try:
        return AppSecrets(
            email_expediteur=st.secrets["EMAIL_EXPEDITEUR"],
            mot_de_passe_email=st.secrets["MOT_DE_PASSE_EMAIL"],
        )
    except Exception:
        st.warning("⚠️ Secrets non configurés — mode démo.")
        return AppSecrets(email_expediteur="", mot_de_passe_email="")


def afficher_interface_expert() -> None:
    st.markdown("""
    <div style="background:linear-gradient(140deg,#0f172a,#1e3a8a);border:1px solid #f59e0b;
                border-radius:14px;padding:20px 24px;margin-bottom:18px">
        <h2 style="color:#fff;margin:0 0 4px">🕵️ Cockpit d'Analyse Expert</h2>
        <p style="color:#94a3b8;margin:0;font-size:.9rem">
            Forensique PDF avancée · Cohérence financière · Rapport transmissible
        </p>
    </div>
    """, unsafe_allow_html=True)

    secrets = get_secrets()

    with st.expander("💸 Message de paiement client (copier-coller)"):
        st.code(
            "Bonjour,\n\n"
            "Afin de lancer l'audit technique de votre dossier, merci de régler les 20 € "
            "d'honoraires via ce lien : [VOTRE LIEN LYDIA / PAYPAL]\n\n"
            "Dès réception, j'analyse les pièces et vous envoie le rapport PDF sous 24h.\n\n"
            "Cordialement,\nNolan — BailSafe",
            language="text",
        )

    fichier_pdf = st.file_uploader("📂 Déposez le PDF à auditer", type="pdf")

    if fichier_pdf is None:
        st.info("Déposez un fichier PDF pour démarrer l'analyse.")
        return

    # Gestion de l'état : on évite de re-parser le PDF à chaque interaction UI
    if "current_pdf_name" not in st.session_state or st.session_state["current_pdf_name"] != fichier_pdf.name:
        with st.spinner("Extraction et analyse du document en cours…"):
            st.session_state["analysis"] = extract_pdf_content(fichier_pdf)
            st.session_state["current_pdf_name"] = fichier_pdf.name
            # Nettoyage des anciens résultats si on change de fichier
            st.session_state.pop("forensic_result", None)

    analysis = st.session_state["analysis"]

    if analysis.error:
        st.warning(f"⚠️ Lecture partielle : {analysis.error}")

    # Calculs lourds ou statiques effectués avant l'affichage des onglets
    if "forensic_result" not in st.session_state:
        st.session_state["forensic_result"] = analyser_forensic(analysis)
    
    forensic = st.session_state["forensic_result"]

    tab1, tab2, tab3 = st.tabs([
        "📊 Cohérence financière",
        "🔎 Forensique PDF",
        "📤 Verdict & Rapport",
    ])

    with tab1:
        est_scan = len(analysis.texte.strip()) < 20

        if est_scan:
            st.warning(
                "⚠️ Aucun texte numérique détecté — PDF scanné ou photo. "
                "Vérification visuelle requise."
            )
            math = MathResult(True, 0, 1, 0, 0, 0, False)
            st.session_state["math_result"] = math
        else:
            st.subheader("Extraction automatique")
            net_auto, cumul_auto = construire_math_result(analysis.texte)

            if net_auto == 0.0:
                st.warning("Aucun montant 'Net à payer' détecté — saisissez manuellement.")
            if cumul_auto == 0.0:
                st.warning("Aucun 'Cumul imposable' détecté — saisissez manuellement.")

            c1, c2, c3 = st.columns(3)
            net_saisi = c1.number_input("Net mensuel (€)", value=net_auto, min_value=0.0, step=10.0)
            nb_mois = c2.number_input("Mois cumulés", value=1, min_value=1, max_value=12)
            cumul_saisi = c3.number_input("Cumul imposable (€)", value=cumul_auto, min_value=0.0, step=10.0)

            math = analyser_math(analysis.texte, net_saisi, int(nb_mois), cumul_saisi)
            st.session_state["math_result"] = math

            seuil = max(100.0, math.calcul_theorique * 0.08)

            m1, m2, m3 = st.columns(3)
            m1.metric("Cumul théorique", f"{math.calcul_theorique:.2f} €")
            m2.metric("Écart constaté", f"{math.ecart:.2f} €",
                      delta=f"{math.ecart:.2f} €" if math.ecart > 0 else None,
                      delta_color="inverse" if math.fraude_math else "off")
            m3.metric("Seuil d'alerte", f"{seuil:.2f} €",
                      help="8 % du cumul théorique, minimum 100 €")

            if math.fraude_math:
                st.error(f"🚨 Écart de {math.ecart:.2f} € — dépasse le seuil de {seuil:.2f} €")
            else:
                st.success("✅ Cohérence mathématique validée.")

    with tab2:
        st.subheader("Analyse forensique complète")
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Intégrité du fichier**")
            st.code(f"SHA-256 : {forensic.hash_sha256[:32]}…", language="text")
            status_xref = "🔴 Anormal (>2 sections)" if forensic.xref_anormal else "🟢 Normal"
            st.markdown(f"Sections xref : `{status_xref}`")
            st.caption("Plus de 2 sections xref = PDF remanié ou reconstruit.")

        with col_b:
            st.markdown("**Signaux suspects**")
            rows = [
                ("Outils d'édition graphique", forensic.fraude_meta,
                 ", ".join(forensic.logiciels_detectes) or "Aucun"),
                ("JavaScript dans le PDF", forensic.javascript_suspect, ""),
                ("Fichiers incorporés", forensic.fichiers_incorpores, ""),
                ("Polices suspectes", len(forensic.fonts_suspectes) > 0,
                 ", ".join(forensic.fonts_suspectes) or "Aucune"),
            ]
            for label, flag, detail in rows:
                icon = "🔴" if flag else "🟢"
                suffix = f" — {detail}" if detail else ""
                st.markdown(f"{icon} {label}{suffix}")

        st.divider()
        st.markdown(f"**Score forensique : {forensic.score_risque_forensic}/100**")
        st.progress(forensic.score_risque_forensic / 100)

        if forensic.score_risque_forensic == 0:
            st.success("Aucun signal forensique détecté.")
        elif forensic.score_risque_forensic < 40:
            st.warning("Signaux faibles — à surveiller.")
        else:
            st.error("Signaux forts — document suspect.")

        st.markdown("**Métadonnées brutes**")
        if analysis.metadata:
            for k, v in analysis.metadata.items():
                st.text(f"{k}: {v}")
        else:
            st.caption("Aucune métadonnée disponible.")

    with tab3:
        math_r = st.session_state.get("math_result")
        forensic_r = st.session_state.get("forensic_result")

        if math_r is None or forensic_r is None:
            st.warning("Veuillez d'abord consulter les onglets précédents pour finaliser l'analyse.")
            return

        verdict = calculer_verdict(math_r, forensic_r)

        if verdict.score_risque >= 80:
            st.error(f"🔴 {verdict.statut}")
        elif verdict.score_risque >= 50:
            st.warning(f"🟠 {verdict.statut}")
        else:
            st.success(f"🟢 {verdict.statut}")

        st.markdown(f"**Score de risque global : {verdict.score_risque}/100**")
        st.progress(verdict.score_risque / 100)

        st.markdown("### Recommandations")
        if verdict.score_risque >= 80:
            recs = [
                "Bloquer la validation — demander l'original du document.",
                "Exiger une pièce justificative complémentaire.",
                "Conserver ce rapport dans le dossier candidat.",
            ]
        elif verdict.score_risque >= 50:
            recs = [
                "Alerter le bailleur sur les anomalies détectées.",
                "Vérification humaine rapide recommandée avant signature.",
                "Demander une explication au candidat sur les incohérences.",
            ]
        else:
            recs = [
                "Dossier conforme — conserver avec suivi standard.",
                "Ce rapport peut servir de justificatif de rigueur.",
            ]
        for r in recs:
            st.markdown(f"- {r}")

        st.divider()

        email_client = st.text_input(
            "Adresse email du client :",
            placeholder="client@exemple.com",
        )

        pdf_bytes = build_report_pdf(verdict, forensic_r)
        filename = get_report_filename(verdict.statut)

        c_send, c_dl = st.columns(2)
        with c_send:
            if st.button("🚀 Envoyer le rapport par email"):
                if not is_valid_email(email_client):
                    st.error("Veuillez saisir une adresse email valide avant d'envoyer.")
                else:
                    with st.spinner("Envoi du rapport en cours..."):
                        ok, msg = envoyer_rapport(secrets, email_client, pdf_bytes, filename)
                        if ok:
                            st.success(msg)
                        else:
                            st.error(msg)

        with c_dl:
            st.download_button(
                label="⬇️ Télécharger le rapport PDF",
                data=pdf_bytes,
                file_name=filename,
                mime="application/pdf",
            )


def main() -> None:
    st.set_page_config(
        page_title="BailSafe | Expert",
        page_icon="🕵️",
        layout="centered",
    )
    afficher_interface_expert()


if __name__ == "__main__":
    main()
