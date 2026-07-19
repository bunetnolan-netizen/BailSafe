"""Tests des fonctions pures d'app_expert.py (extraction, scoring, cohérence croisée).
N'exerce pas l'interface Streamlit elle-même — seulement les fonctions appelables
indépendamment de st.session_state."""

import app_expert as app


# ============== _to_float / construire_math_result ==============

def test_to_float_formats_francais():
    assert app._to_float("1 234,56") == 1234.56
    assert app._to_float("1.234,56") == 1234.56
    assert app._to_float("1234.56") == 1234.56
    assert app._to_float("2000") == 2000.0


def test_to_float_invalide_renvoie_zero():
    assert app._to_float("abc") == 0.0


def test_construire_math_result_extrait_net_et_cumul():
    texte = "Net imposable : 2 000,00 EUR ... Cumul imposable : 24 000,00 EUR"
    net, cumul = app.construire_math_result(texte)
    assert net == 2000.0
    assert cumul == 24000.0


def test_construire_math_result_absent_renvoie_zero():
    net, cumul = app.construire_math_result("aucun montant ici")
    assert net == 0.0
    assert cumul == 0.0


# ============== analyser_math ==============

def test_analyser_math_coherent():
    result = app.analyser_math(2000.0, 12, 24000.0)
    assert result.fraude_math is False
    assert result.calcul_theorique == 24000.0


def test_analyser_math_incoherent_au_dela_du_seuil():
    result = app.analyser_math(2000.0, 12, 10000.0)
    assert result.fraude_math is True


def test_analyser_math_tolerance_8_pourcent():
    # écart de 5% (1200 sur 24000) : sous le seuil de 8% -> pas de fraude
    result = app.analyser_math(2000.0, 12, 22800.0)
    assert result.fraude_math is False


def test_analyser_math_valeurs_nulles_pas_de_fraude():
    result = app.analyser_math(0.0, 1, 0.0)
    assert result.fraude_math is False


# ============== calculer_verdict ==============

def test_calculer_verdict_conforme():
    math = app.MathResult(False, 0, 24000, 2000, 12, 24000, False)
    forensic = app.ForensicResult(hash_sha256="a", incremental_updates=1,
                                  xref_anormal=False, fraude_meta=False,
                                  score_risque_forensic=0)
    verdict = app.calculer_verdict(math, forensic)
    assert verdict.score_risque < 40
    assert verdict.statut.startswith("🟢")


def test_calculer_verdict_anomalies_majeures():
    math = app.MathResult(False, 0, 24000, 2000, 12, 10000, True)
    forensic = app.ForensicResult(hash_sha256="a", incremental_updates=3,
                                  xref_anormal=True, fraude_meta=True,
                                  logiciels_detectes=["Photoshop"],
                                  score_risque_forensic=90)
    verdict = app.calculer_verdict(math, forensic)
    assert verdict.score_risque >= 70
    assert verdict.statut.startswith("🔴")


# ============== analyser_forensic ==============

def _pdf_analysis(raw_bytes: bytes, metadata=None) -> "app.PDFAnalysis":
    return app.PDFAnalysis(texte="", metadata=metadata or {}, raw_bytes=raw_bytes,
                           hash_sha256="x")


def test_analyser_forensic_pdf_propre():
    raw = b"%PDF-1.4\n...\n%%EOF"
    result = app.analyser_forensic(_pdf_analysis(raw))
    assert result.xref_anormal is False
    assert result.signature_detectee is False
    assert result.score_risque_forensic == 0


def test_analyser_forensic_xref_anormal_sans_signature():
    # 3 %%EOF = 2 mises à jour incrémentielles au-delà de l'original, sans /ByteRange
    raw = b"%PDF-1.4\n%%EOF\n...\n%%EOF\n...\n%%EOF"
    result = app.analyser_forensic(_pdf_analysis(raw))
    assert result.xref_anormal is True
    assert result.score_risque_forensic >= 30


def test_analyser_forensic_xref_explique_par_signature():
    # 2 %%EOF (1 mise à jour) expliquée par 1 /ByteRange -> pas anormal
    raw = b"%PDF-1.4\n%%EOF\n/ByteRange [0 1 2 3]\n%%EOF"
    result = app.analyser_forensic(_pdf_analysis(raw))
    assert result.signature_detectee is True
    assert result.xref_anormal is False


def test_analyser_forensic_outil_edition_detecte():
    raw = b"%PDF-1.4\n%%EOF"
    metadata = {"Créateur": "Adobe Photoshop 2023", "Producteur": "N/A", "Auteur": "N/A"}
    result = app.analyser_forensic(_pdf_analysis(raw, metadata))
    assert result.fraude_meta is True
    assert "Photoshop" in result.logiciels_detectes


def test_analyser_forensic_producteur_legitime_pas_de_faux_positif():
    raw = b"%PDF-1.4\n%%EOF"
    metadata = {"Créateur": "N/A", "Producteur": "Microsoft: Print To PDF", "Auteur": "N/A"}
    result = app.analyser_forensic(_pdf_analysis(raw, metadata))
    assert result.fraude_meta is False


# ============== is_valid_email / get_report_filename ==============

def test_is_valid_email():
    assert app.is_valid_email("client@exemple.com") is True
    assert app.is_valid_email("pas-un-email") is False


def test_get_report_filename_dossier_suffix():
    assert "_Dossier" in app.get_report_filename("🔴 x", dossier=True)
    assert "_Dossier" not in app.get_report_filename("🔴 x", dossier=False)


def test_get_report_filename_par_statut():
    assert app.get_report_filename("🔴 x").startswith("BailSafe_ALERTE")
    assert app.get_report_filename("🟠 x").startswith("BailSafe_ATTENTION")
    assert app.get_report_filename("🟢 x").startswith("BailSafe_CONFORME")


# ============== analyser_dossier_croise / calculer_verdict_dossier ==============

def _doc(nom, type_doc, hash_sha256, forensic_score=0, net_imposable=0.0,
        fraude_math=False):
    analysis = app.PDFAnalysis(texte="", metadata={}, raw_bytes=b"", hash_sha256=hash_sha256)
    forensic = app.ForensicResult(hash_sha256=hash_sha256, incremental_updates=1,
                                  xref_anormal=False, fraude_meta=False,
                                  score_risque_forensic=forensic_score)
    math = app.MathResult(False, 0, net_imposable * 12, net_imposable, 12,
                          net_imposable * 12, fraude_math)
    return app.DocumentAnalyse(nom_fichier=nom, type_document=type_doc,
                               analysis=analysis, forensic=forensic, math=math)


def test_analyser_dossier_croise_detecte_doublons():
    d1 = _doc("a.pdf", "Autre", hash_sha256="same")
    d2 = _doc("b.pdf", "Autre", hash_sha256="same")
    cross = app.analyser_dossier_croise([d1, d2])
    assert cross.doublons_detectes is True
    assert set(cross.fichiers_dupliques) == {"a.pdf", "b.pdf"}


def test_analyser_dossier_croise_pas_de_doublon():
    d1 = _doc("a.pdf", "Autre", hash_sha256="h1")
    d2 = _doc("b.pdf", "Autre", hash_sha256="h2")
    cross = app.analyser_dossier_croise([d1, d2])
    assert cross.doublons_detectes is False


def test_analyser_dossier_croise_ecart_fiches_paie():
    d1 = _doc("paie1.pdf", "Fiche de paie", hash_sha256="h1", net_imposable=2000)
    d2 = _doc("paie2.pdf", "Fiche de paie", hash_sha256="h2", net_imposable=1000)
    cross = app.analyser_dossier_croise([d1, d2])
    assert cross.incoherence_financiere is True
    assert len(cross.ecarts_fiches_paie) == 1


def test_analyser_dossier_croise_fiches_paie_stables():
    d1 = _doc("paie1.pdf", "Fiche de paie", hash_sha256="h1", net_imposable=2000)
    d2 = _doc("paie2.pdf", "Fiche de paie", hash_sha256="h2", net_imposable=2050)
    cross = app.analyser_dossier_croise([d1, d2])
    assert cross.incoherence_financiere is False


def test_calculer_verdict_dossier_retient_le_max_forensique():
    d1 = _doc("a.pdf", "Autre", hash_sha256="h1", forensic_score=5)
    d2 = _doc("b.pdf", "Autre", hash_sha256="h2", forensic_score=90)
    cross = app.CrossDocResult(nb_documents=2)
    verdict = app.calculer_verdict_dossier([d1, d2], cross)
    # score_global = 0.6*90 = 54 (pas de fraude math, pas de croisement)
    assert verdict.score_risque == 54


def test_calculer_verdict_dossier_penalite_doublons():
    d1 = _doc("a.pdf", "Autre", hash_sha256="h1", forensic_score=0)
    cross = app.CrossDocResult(nb_documents=1, doublons_detectes=True)
    verdict = app.calculer_verdict_dossier([d1], cross)
    assert verdict.score_risque == 20


def test_calculer_verdict_dossier_vide():
    verdict = app.calculer_verdict_dossier([], app.CrossDocResult(nb_documents=0))
    assert verdict.score_risque == 0


# ============== Rapports PDF (smoke tests) ==============

def test_build_report_pdf_produit_un_pdf_valide():
    math = app.MathResult(False, 0, 24000, 2000, 12, 24000, False)
    forensic = app.ForensicResult(hash_sha256="a" * 10, incremental_updates=1,
                                  xref_anormal=False, fraude_meta=False,
                                  score_risque_forensic=0)
    verdict = app.calculer_verdict(math, forensic)
    pdf_bytes = app.build_report_pdf(verdict, forensic, math)
    assert pdf_bytes.startswith(b"%PDF")


def test_build_dossier_report_pdf_produit_un_pdf_valide():
    d1 = _doc("a.pdf", "Fiche de paie", hash_sha256="h1", net_imposable=2000)
    d2 = _doc("b.pdf", "Fiche de paie", hash_sha256="h2", net_imposable=2000)
    cross = app.analyser_dossier_croise([d1, d2])
    verdict = app.calculer_verdict_dossier([d1, d2], cross)
    pdf_bytes = app.build_dossier_report_pdf(verdict, [d1, d2], cross)
    assert pdf_bytes.startswith(b"%PDF")
