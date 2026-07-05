# BailSafe — Instructions pour Claude Code

**Projet :** BailSafe — audit anti-fraude documentaire pour bailleurs (39 € TTC/dossier).
**Auteur :** Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe.
**Repo :** https://github.com/bunetnolan-netizen/BailSafe (branche `main`).
**Vitrine en ligne :** https://bailsafe.netlify.app/

Pour le détail technique exhaustif (dataclasses, fonctions, sections HTML, scoring
forensique...), voir `NOLAN_BAILSAFE_contexte.md`. Pour l'hébergement, le flux de commande
et les TODOs de mise en prod, voir `BAILSAFE_CONTEXTE.md`. Ce fichier-ci est le point
d'entrée résumé + le journal de bord des sessions.

## Stack

- Python + Streamlit (`app_expert.py` = interface d'analyse, protégée par mot de passe)
- `index.html` = vitrine standalone HTML/CSS/JS, **en ligne sur Netlify** (https://bailsafe.netlify.app/),
  ne pas confondre avec `archive/app_vitrine.py` qui est **archivé, ne plus utiliser**
- ReportLab pour le rapport PDF, pdfplumber/pikepdf pour l'extraction/analyse PDF
- Secrets via `os.getenv()` puis `st.secrets` (jamais commités — voir `secrets.toml.example`)

## Règles de travail

- **Git/GitHub : automatisé (depuis le 4 juillet 2026).** Le dépôt local est initialisé et
  connecté à `origin` (GitHub). Claude peut committer et pousser directement sans redemander
  à chaque fois, sauf pour des opérations destructives (force-push, réécriture d'historique,
  suppression de branche) qui restent à confirmer avec Nolan au préalable.
- La vitrine publique (`index.html`) est déployée sur **Netlify** : https://bailsafe.netlify.app/
  (confirmé par Nolan le 4 juillet 2026 — pas de migration à faire, contrairement à ce
  qu'indiquaient les anciennes notes de `BAILSAFE_CONTEXTE.md`/`NOLAN_BAILSAFE_contexte.md`).
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
  https://bailsafe.netlify.app/ — la migration n'est plus un TODO.

**TODO manuels restants (hors de portée de l'agent) :**
- Créer un vrai formulaire Formspree (ou alternative hébergée UE) et remplacer l'ID placeholder.
- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`.
