# BailSafe — Instructions pour Claude Code

**Projet :** BailSafe — audit anti-fraude documentaire pour bailleurs (3 formules : Essentiel 59 €, Sécurisé 129 €, Dossier Complet 229 € TTC).
**Auteur :** Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe.
**Repo :** https://github.com/bunetnolan-netizen/BailSafe (branche `main`).
**Vitrine en ligne :** https://bail-safe.netlify.app/ (attention à ne pas confondre avec
`bailsafe.netlify.app` sans tiret, qui n'est pas ce site)

Pour le détail technique exhaustif (dataclasses, fonctions, sections HTML, scoring
forensique...), voir `NOLAN_BAILSAFE_contexte.md`. Pour l'hébergement, le flux de commande
et les TODOs de mise en prod, voir `BAILSAFE_CONTEXTE.md`. Ce fichier-ci est le point
d'entrée résumé + le journal de bord des sessions.

## Stack

- Python + Streamlit (`app_expert.py` = interface d'analyse, protégée par mot de passe)
- `index.html` = vitrine standalone HTML/CSS/JS, **en ligne sur Netlify** (https://bail-safe.netlify.app/)
  — c'est la seule vitrine du projet (l'ancienne version Streamlit `app_vitrine.py` a été
  supprimée du dépôt le 18 juillet 2026, récupérable via `git log` si besoin)
- ReportLab pour le rapport PDF, pdfplumber/pikepdf pour l'extraction/analyse PDF
- Secrets via `os.getenv()` puis `st.secrets` (jamais commités — voir `secrets.toml.example`)

## Règles de travail

- **Git/GitHub : automatisé (depuis le 4 juillet 2026).** Le dépôt local est initialisé et
  connecté à `origin` (GitHub). Claude peut committer et pousser directement sans redemander
  à chaque fois, sauf pour des opérations destructives (force-push, réécriture d'historique,
  suppression de branche) qui restent à confirmer avec Nolan au préalable.
- La vitrine publique (`index.html`) est déployée sur **Netlify** : https://bail-safe.netlify.app/
  — **connectée au dépôt GitHub pour l'auto-déploiement** (confirmé par Nolan le 4 juillet
  2026). Chaque push sur `main` redéploie automatiquement la vitrine, comme Render pour
  `app_expert.py`. Plus besoin de redéployer manuellement ni de vérifier ce point.
- Les TODOs bloquants (URL Render, mot de passe expert...) sont listés dans
  `BAILSAFE_CONTEXTE.md` — ne pas les inventer, demander à Nolan les valeurs réelles.
- RGPD : conservation 30 jours max, aucune décision automatisée (art. 22), information
  candidat obligatoire (art. 13/14) — voir `MODELE_INFORMATION_CANDIDAT.md`.
- **Formulaire de commande : Brevo (UE, Paris) via fonction serverless Netlify**
  (`netlify/functions/order.js`), plus Formspree. Variables d'environnement requises dans
  Netlify (Site configuration → Environment variables) : `BREVO_API_KEY`, `BREVO_SENDER_EMAIL`
  (adresse vérifiée comme expéditeur dans Brevo), `BREVO_SENDER_NAME` (optionnel, "BailSafe"
  par défaut), `BAILSAFE_NOTIF_EMAIL` (optionnel, sinon bunetnolan@gmail.com par défaut).

## Journal de session

À la fin de chaque session avec des changements substantiels, ajoute une entrée ici :
date, ce qui a été fait, ce qui reste en TODO manuel pour Nolan. Garde chaque entrée courte
(quelques lignes) — le détail technique va dans le code ou les fichiers de contexte, pas ici.

### 4 juillet 2026

- Réduction des faux positifs forensiques : `xref_anormal` ignore les mises à jour
  incrémentielles expliquées par une signature électronique (`/ByteRange`).
- `date_modifiee` : poids réduit (15 → 5 pts), neutralisé si document signé.
- `/Stamp` retiré des annotations suspectes (cachets légitimes) ; `/FreeText` et `/Redact` gardés.
- Nouveau champ `signature_detectee` affiché dans l'onglet forensique et le rapport PDF.
- `check_password()` : comparaison à temps constant (`hmac.compare_digest`).
- RGPD : date de purge (+30j) ajoutée dans l'email bailleur et le rapport ; avertissement
  Schrems II ajouté dans `index.html` pour Formspree (hors UE) ; nouveau fichier
  `MODELE_INFORMATION_CANDIDAT.md` (info candidat art. 13/14).
- `app_vitrine.py` déplacé dans `archive/` (doublon de `index.html`, contenait un lien Stripe
  de test) — déplacé et non supprimé pour rester réversible.
- Création de ce `CLAUDE.md` comme point d'entrée résumé + journal de session.
- Configuration Claude Code : permissions PowerShell élargies (`Get-ChildItem`, `Test-Path`,
  `python *`), hook de vérification syntaxe auto sur `app_expert.py` (inactif tant que Python
  n'est pas réellement installé — seul le stub Windows Store est présent).
- **Passage à Git/GitHub automatisé** : Git for Windows installé, dépôt local initialisé et
  relié à `origin`. Historique GitHub existant (60+ commits "Update X.py" issus de l'ancien
  workflow copier-coller) fusionné avec `--allow-unrelated-histories -X ours` pour préserver
  la traçabilité sans perdre l'état local. Nettoyage au passage : suppression d'un fichier
  `download` (upload accidentel) et d'un `app_vitrine.py` racine obsolète (doublon de la
  version archivée). Premier push effectué avec succès.
- Confirmation de Nolan : la vitrine (`index.html`) est en ligne sur **Netlify** —
  https://bail-safe.netlify.app/ — connectée à GitHub pour l'auto-déploiement, comme Render.
  Les deux hébergements se redéploient automatiquement à chaque push, sans action manuelle.
- Correction du domaine placeholder dans les balises `canonical`/`og:url` d'`index.html`
  (remplacé par l'URL Netlify réelle).
- **Remplacement de Formspree par Brevo (UE)** pour le formulaire de commande : nouvelle
  fonction serverless `netlify/functions/order.js` (relaie vers l'API transactionnelle Brevo,
  clé API jamais exposée côté client), `netlify.toml` ajouté pour déclarer le dossier de
  fonctions. `index.html` mis à jour pour poster vers `/.netlify/functions/order` au lieu de
  Formspree ; l'avertissement Schrems II n'a plus lieu d'être (plus de transfert hors UE).

**TODO manuels restants (hors de portée de l'agent) :**
- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`.

---

### 5 juillet 2026

- **Compte Brevo créé et configuré** : sender vérifié, `BREVO_API_KEY`/`BREVO_SENDER_EMAIL`
  posés dans Netlify. Formulaire de commande testé de bout en bout (site → fonction Netlify →
  Brevo → boîte Gmail) — fonctionnel.
- **UX** : incohérence chiffrée corrigée (18 mois d'expulsion partout), email de confirmation
  client ajouté (récap étapes + PayPal + email de Nolan, filet de sécurité si le client ferme
  l'onglet), nuance sur "déductible selon régime fiscal" (au lieu de "100% déductible").
- **Repositionnement "high ticket"** : passage d'un prix unique (39 €) à 3 formules —
  Essentiel (59 €, 1 document), Sécurisé (129 €, 2 documents, cohérence croisée, mis en avant),
  Dossier Complet (229 €, jusqu'à 4 documents, traitement prioritaire). Nouveau champ
  "Formule" dans le formulaire, montant PayPal et emails (notification + confirmation)
  calculés dynamiquement selon la formule choisie. Couleur CTA dédiée (orange chaud) distincte
  du rouge "danger forensique", halo pulsant sur le bouton final, garantie remboursement
  remontée juste sous le premier bouton.
  **Important — non fait** : `app_expert.py` ne sait analyser qu'un seul PDF à la fois.
  Les formules Sécurisé/Dossier Complet nécessitent que Nolan passe chaque document
  séparément dans l'outil et compile lui-même la cohérence entre documents pour l'instant —
  automatiser cette analyse croisée est un chantier à part, pas fait dans cette session.
- **Anomalie détectée (à surveiller, pas un bug de code)** : le 2e email d'une paire
  (confirmation client) part bien de la fonction Netlify et Brevo répond succès, mais reste
  en statut **"Delayed"** dans Brevo → Transactional → Email Activity. Cause probable : compte
  Brevo créé le jour même, période de montée en confiance/anti-abus classique chez les ESP
  pour un compte tout neuf. Devrait se résorber sous 24-48h sans action. À revérifier ; si
  toujours bloqué après 48h, contacter le support Brevo.
- Correction d'un bug d'encodage que j'avais moi-même introduit en modifiant
  `BAILSAFE_CONTEXTE.md` via PowerShell `Get-Content`/`Set-Content` (mojibake sur les
  accents) — restauré depuis git puis corrigé avec l'outil d'édition.
- **Alerte Render à vérifier** : email reçu de Render le 5 juillet à 12h21 — *"Server failure
  detected on BailSafe-expert"*. Pas d'investigation plus poussée faite dans cette session
  (hors sujet du moment) — Nolan à vérifier que l'app expert tourne toujours normalement.

**TODO manuels restants :**
- Vérifier le statut Brevo (Delayed → Delivered) dans les 24-48h.
- Vérifier l'alerte de panne Render du 5 juillet et confirmer que `app_expert.py` fonctionne.
- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`.
- Décider si/quand automatiser l'analyse multi-documents dans `app_expert.py` pour les
  formules Sécurisé et Dossier Complet (actuellement traitement manuel par Nolan).

---

### 18 juillet 2026

- **Analyse multi-documents automatisée** (le point resté en TODO depuis le 5 juillet) :
  `app_expert.py` permet désormais de choisir la formule commandée (Essentiel/Sécurisé/Dossier
  Complet) et d'uploader jusqu'à 1/2/4 PDF en une seule session. Chaque document est analysé
  individuellement (forensique + cohérence financière, UI par onglets/expandeurs), puis une
  **cohérence croisée** est calculée : détection de fichiers identiques déposés en double, et
  détection d'écarts anormaux (>30 %) entre plusieurs fiches de paie du même dossier. Le
  verdict global retient le **score forensique le plus élevé** parmi les documents (pas une
  moyenne, pour ne pas diluer un document falsifié par des pièces saines) + une pénalité si
  doublon/incohérence détectée. Un rapport PDF combiné (une section par document + synthèse de
  cohérence) est généré et envoyé/téléchargé en un seul geste. Nouvelles fonctions :
  `analyser_dossier_croise()`, `calculer_verdict_dossier()`, `build_dossier_report_pdf()`.
  Au passage, correction d'un bug de mise en page ReportLab (texte long non enveloppé dans
  `_signal_table`, chevauchait la pastille de statut).
- **Tests automatisés ajoutés** : le projet n'en avait aucun. Nouveau `tests/test_app_expert.py`
  (27 tests pytest) couvrant les fonctions pures — parsing montants, cohérence financière,
  scoring forensique, et toute la nouvelle logique multi-documents. `pytest>=8.0` ajouté à
  `requirements.txt`. Pas de CI GitHub Actions mise en place (à voir si utile).
- `archive/app_vitrine.py` (ancienne vitrine Streamlit dépréciée, doublon d'`index.html`)
  **supprimé** du dépôt — décision en TODO depuis le 4 juillet, tranchée : plus aucune raison
  de la garder, reste récupérable via l'historique git.
- Explication donnée à Nolan sur le statut Brevo "Delayed" vs "Delivered" (aucun changement de
  code — c'est un statut à vérifier dans le tableau de bord Brevo lui-même).

**TODO manuels restants :**
- Vérifier le statut Brevo (Delayed → Delivered) — à confirmer par Nolan dans le dashboard.
- Vérifier l'alerte de panne Render du 5 juillet et confirmer que `app_expert.py` fonctionne.
- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`.

---

### 5 août 2026 (session marathon)

- **V3** (commits `ba3dd05`, `12b5b6d`, `325e5d4`, `1224b48`, `f15f45f`) : refonte complète.
- **Prix** : Essentiel 69 €, Sécurisé 149 €, Dossier Complet 299 € (scénario B).
- **Paiement** : retour à PayPal paypal.me/NolanBunet (Stripe n'était pas câblé).
- **Tunnel de vente** : récap commande visible, urgence réaliste (« 24h, souvent le jour même »), garantie remboursement, barre de confiance, FAQ 10 questions, cas concrets (3 scénarios), filet indécis (email).
- **Logo** : écusson loupe+dossier extrait d'une image source, fond blanc→transparent, positionné entre BAIL et SAFE (30px, gap 3px), navbar #1C2B29.
- **Aperçu rapport** : simplifié — badge + verdict + tableau 4 critères + barre dégradé rouge→vert.
- **Ton corporate** : « nous/équipe » partout, nom/ville uniquement dans les docs légaux obligatoires.
- **Email confirmation** : bouton PayPal intégré, statut « en attente de paiement ».
- **Backend** : order.js prix + email + ton corporate. app_expert.py FORMULES.
- **Démo systématique** avant chaque commit sur localhost:8888.
- **Tests** : 27/27 ✅.

**TODO manuels :**
- Définir le rôle du bot Telegram BailSafe (client et/ou admin).
- Créer un compte Stripe quand possible pour basculer vers du paiement CB intégré.
