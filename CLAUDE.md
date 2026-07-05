# BailSafe — Instructions pour Claude Code

**Projet :** BailSafe — audit anti-fraude documentaire pour bailleurs (39 € TTC/dossier).
**Auteur :** Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe.
**Repo :** https://github.com/bunetnolan-netizen/BailSafe (branche `main`).

Pour le détail technique exhaustif (dataclasses, fonctions, sections HTML, scoring
forensique...), voir `NOLAN_BAILSAFE_contexte.md`. Pour l'hébergement, le flux de commande
et les TODOs de mise en prod, voir `BAILSAFE_CONTEXTE.md`. Ce fichier-ci est le point
d'entrée résumé + le journal de bord des sessions.

## Stack

- Python + Streamlit (`app_expert.py` = interface d'analyse, protégée par mot de passe)
- `index.html` = vitrine standalone HTML/CSS/JS (à déployer sur Netlify, ne pas confondre
  avec `archive/app_vitrine.py` qui est **archivé, ne plus utiliser**)
- ReportLab pour le rapport PDF, pdfplumber/pikepdf pour l'extraction/analyse PDF
- Secrets via `os.getenv()` puis `st.secrets` (jamais commités — voir `secrets.toml.example`)

## Règles de travail

- Ce dépôt n'est pas un repo git initialisé localement (`git init` pas encore fait). Ne pas
  lancer de commandes git/push sans que Nolan le demande explicitement.
- **GitHub : étapes manuelles uniquement.** Nolan préfère des instructions copier-coller pour
  l'interface web GitHub plutôt que des installs/push git automatisés par l'agent.
- Les TODOs bloquants (ID Formspree placeholder, URL Render, mot de passe expert...) sont
  listés dans `BAILSAFE_CONTEXTE.md` — ne pas les inventer, demander à Nolan les valeurs réelles.
- RGPD : conservation 30 jours max, aucune décision automatisée (art. 22), information
  candidat obligatoire (art. 13/14) — voir `MODELE_INFORMATION_CANDIDAT.md`.

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

**TODO manuels restants (hors de portée de l'agent) :**
- Créer un vrai formulaire Formspree (ou alternative hébergée UE) et remplacer l'ID placeholder.
- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`.
- Décider si `archive/app_vitrine.py` doit être retiré du dépôt GitHub distant.
