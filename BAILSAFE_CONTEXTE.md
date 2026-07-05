# BailSafe — Fiche Contexte Projet

**Dernière mise à jour :** 29 juin 2026  
**Créateur :** Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe

---

## C'est quoi

Service d'audit anti-fraude documentaire pour propriétaires bailleurs. Le client envoie un PDF (fiche de paie, avis d'imposition, contrat de travail, relevé bancaire) — BailSafe réalise une analyse forensique et renvoie un rapport PDF sous 24h.

**Prix :** 39 € TTC par dossier  
**Paiement :** PayPal uniquement — paypal.me/NolanBunet/39EUR

---

## Architecture technique

### Stack
- **Langage :** Python
- **Framework :** Streamlit (app_vitrine + app_expert)
- **Génération rapport :** ReportLab (PDF)
- **Extraction PDF :** pdfplumber
- **Formulaire de commande :** Formspree
- **Vitrine standalone :** HTML/CSS/JS pur (index.html)

### Fichiers principaux

| Fichier | Rôle | Hébergement |
|---|---|---|
| `app_expert.py` | Interface d'analyse pour Nolan | Render (BailSafe-expert) |
| `index.html` | Vitrine standalone — **version à déployer** | À déployer sur Netlify |
| `MODELE_INFORMATION_CANDIDAT.md` | Modèle d'info RGPD art. 13/14 à remettre au candidat | — |
| `archive/app_vitrine.py` | Ancienne landing page Streamlit — **archivée, ne plus utiliser** | bail-safe.streamlit.app (tant que non redéployé) |

---

## Hébergements

### Vitrine publique (landing page)
- **Actuel :** https://bail-safe.streamlit.app — hébergé sur Streamlit Cloud
- **Problème :** interface Streamlit visible autour de la page, pas plein écran
- **À migrer vers :** `index.html` standalone sur Netlify (fichier prêt)

### App Expert (interface d'analyse)
- **Hébergeur :** Render
- **URL :** https://[NOM-DU-SERVICE].onrender.com ← **à compléter**
- **Protection :** variable d'environnement `EXPERT_PASSWORD` à définir dans Render → Settings → Environment Variables
- **Variables d'env requises sur Render :**
  - `EXPERT_PASSWORD` = [mot de passe choisi par Nolan]
  - `EMAIL_EXPEDITEUR` = adresse Gmail d'envoi
  - `MOT_DE_PASSE_EMAIL` = App Password Gmail (pas le mot de passe Gmail principal)

### GitHub (source de vérité)
- **Repo :** https://github.com/bunetnolan-netizen/BailSafe
- **Branche principale :** `main`

### Futur — Netlify (vitrine standalone)
- Déployer le fichier `index.html` sur netlify.com
- Drag & drop du fichier → URL générée en 30 secondes
- Option : connecter directement au repo GitHub pour déploiement automatique sur push

---

## Flux de commande (côté client)

1. Client arrive sur la vitrine (Netlify ou Streamlit)
2. Remplit le formulaire → envoi via **Formspree** → Nolan reçoit un email
3. Client est redirigé vers le bouton PayPal pour payer 39 €
4. Nolan reçoit le paiement PayPal → récupère le PDF du client par email
5. Nolan dépose le PDF dans **app_expert** → analyse automatique
6. Nolan télécharge le rapport PDF généré → l'envoie au client par email

---

## Ce que détecte l'analyse forensique

- **SHA-256** calculé sur les bytes bruts du fichier (intégrité réelle)
- **Sections xref** multiples = PDF remanié après émission (incremental updates)
- **Outils d'édition** dans les métadonnées (Photoshop, Canva, GIMP, Affinity...)
- **JavaScript embarqué** dans le PDF
- **Fichiers incorporés** suspects
- **Cohérence financière** : net mensuel × nombre de mois vs cumul imposable déclaré

**Limite importante (à communiquer aux clients) :** un document imprimé puis re-scanné après modification échappe à l'analyse forensique numérique.

---

## Configuration à compléter (TODOs bloquants)

| Quoi | Où | Comment |
|---|---|---|
| ID Formspree | `index.html` ligne ~380 | Créer un formulaire sur formspree.io → copier l'URL |
| EXPERT_PASSWORD | Render → Environment Variables | Choisir un mot de passe fort, le noter |
| EMAIL_EXPEDITEUR | Render → Environment Variables | Ex : bunetnolan@gmail.com |
| MOT_DE_PASSE_EMAIL | Render → Environment Variables | App Password Gmail (Google → Sécurité → Mots de passe des applications) |
| URL Render expert | Ce fichier | Compléter l'URL de l'app expert Render ci-dessus |

---

## Canaux de distribution

| Canal | Statut | Rôle |
|---|---|---|
| Vitrine web | ✅ En ligne (Streamlit) / 🔄 Migration Netlify | Acquisition principale |
| Email direct | ✅ bunetnolan@gmail.com | Fallback commande |
| Facebook | ✅ Actif | Communauté / organique |
| LeBonCoin | ⚠️ Retiré du CTA principal | Garde en lien discret |

---

## RGPD — Points clés

- Données conservées **30 jours maximum**
- PDF analysés en mémoire (session Streamlit), non stockés
- Checkbox obligatoire : bailleur confirme avoir **informé le candidat** (art. 14 RGPD)
- Le rapport est un **avis technique consultatif** — aucune décision automatisée (art. 22 RGPD)
- Documents légalement exigibles uniquement (décret n°2015-1437)
- Droit d'accès/suppression : bunetnolan@gmail.com

---

## Corrections apportées (session juin 2026)

- SHA-256 corrigé : calculé sur les bytes réels du fichier (pas sur les métadonnées)
- `xref_anormal` corrigé : détection réelle via comptage des `startxref` (était hardcodé à `False`)
- `check_password()` corrigé : bloque l'accès si `EXPERT_PASSWORD` non défini (était ouvert)
- Formspree et Stripe : remplacés par des marqueurs clairs à configurer
- Stripe supprimé : PayPal uniquement
- LeBonCoin dépriorisé : formulaire direct en CTA principal
- Disclaimer limite scan/ré-impression : ajouté sur la vitrine et dans le rapport PDF
- Checkbox RGPD candidat : ajoutée au formulaire de commande
- `index.html` standalone créé : vitrine sans Streamlit, prête pour Netlify

---

## Corrections apportées (session 4 juillet 2026)

- **Faux positifs forensiques réduits** : `xref_anormal` ignore désormais les mises à jour
  incrémentielles expliquées par une signature électronique (détection via `/ByteRange`) —
  un document officiel signé numériquement n'est plus pénalisé à tort.
- `date_modifiee` : poids réduit dans le score (15 → 5 points) et neutralisé si le document
  est signé, ce signal étant intrinsèquement peu fiable (resignature, réexport…).
- Annotations suspectes : `/Stamp` retiré des subtypes déclencheurs (cachets de certification
  légitimes trop souvent confondus avec des ajouts frauduleux). `/FreeText` et `/Redact` conservés.
- Nouveau champ `signature_detectee` affiché dans l'onglet forensique et le rapport PDF.
- `check_password()` : comparaison à temps constant (`hmac.compare_digest`) au lieu de `==`.
- **RGPD NC#3 (conservation emails)** : date de purge explicite (+30 jours) ajoutée dans le
  corps de l'email envoyé au bailleur et dans l'encadré légal du rapport PDF.
- **RGPD NC#2 (Formspree hors UE)** : avertissement Schrems II détaillé ajouté dans `index.html`
  au-dessus de `FORMSPREE_URL`, avec alternatives UE suggérées. *Migration réelle vers un
  prestataire UE non faite — nécessite la création d'un compte, à faire manuellement.*
- **RGPD NC#1 (information candidat)** : nouveau fichier `MODELE_INFORMATION_CANDIDAT.md`,
  texte prêt à remettre au candidat (art. 13/14 RGPD) avant transmission de son document.
- `app_vitrine.py` archivé dans `archive/` (doublon de `index.html`, contenait encore le lien
  Stripe de test) — déplacé, pas supprimé, pour rester réversible.

**TODO restants (nécessitent une action manuelle de Nolan, hors de portée d'une correction de code) :**
- Créer un vrai formulaire Formspree (ou son alternative UE) et remplacer l'ID placeholder
- Finaliser le déploiement Render et renseigner son URL
- Décider si `archive/app_vitrine.py` doit être retiré du dépôt GitHub distant

---

## Contacts & accès

| Quoi | Valeur |
|---|---|
| Email Nolan | bunetnolan@gmail.com |
| PayPal | paypal.me/NolanBunet/39EUR |
| GitHub | github.com/bunetnolan-netizen/BailSafe |
| Facebook | https://www.facebook.com/share/1KKBK1mfpV/ |
| Vitrine actuelle | https://bail-safe.streamlit.app |
| App expert | https://[À COMPLÉTER].onrender.com |
