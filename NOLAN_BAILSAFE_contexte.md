# NOLAN BAILSAFE — Contexte projet pour Claude

## Vue d'ensemble

**Projet** : BailSafe — Outil d'audit anti-fraude documentaire pour bailleurs  
**Auteur** : Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe  
**Repo GitHub** : https://github.com/bunetnolan-netizen/BailSafe/tree/main  
**Stack** : `index.html` standalone (vitrine, sur Netlify) + Python/Streamlit `app_expert.py` (interface d'analyse, sur Render)  
**Prix (3 formules depuis le 5 juillet 2026)** : Essentiel 59 €, Sécurisé 129 €, Dossier Complet 229 € TTC  
**Statut** : En production — vitrine sur Netlify (https://bail-safe.netlify.app/), interface expert sur Render.
Note : ce document détaille encore le code de l'ancien `app_vitrine.py` (Streamlit) plus bas —
ce fichier est **archivé** dans `archive/`, remplacé par `index.html`. Voir `CLAUDE.md` pour
l'état actuel du projet.

---

## Architecture

```
bailsafe/
├── app_vitrine.py          ← Page publique (landing + formulaire de commande)
├── app_expert.py           ← Interface d'analyse forensique (accès protégé)
├── requirements.txt
├── .gitignore
└── .streamlit/
    ├── secrets.toml        ← À créer localement (jamais commité)
    └── secrets.toml.example
```

**Principe de fonctionnement :**
1. Le client commande sur la vitrine (https://bail-safe.netlify.app/) et choisit une formule
2. Il paie 59 €, 129 € ou 229 € via PayPal selon la formule choisie
3. Il envoie son ou ses documents par email
4. Nolan ouvre l'interface expert, uploade le(s) document(s), génère le rapport PDF
5. Le rapport est envoyé au client par email via Gmail SMTP

---

## Dépendances (requirements.txt)

```
streamlit>=1.33
pdfplumber>=0.11
pikepdf>=8.0
reportlab>=4.0
```

Standard library utilisée dans app_expert.py : `hashlib`, `os`, `re`, `logging`, `dataclasses`, `datetime`, `typing`, `smtplib`, `email`, `io.BytesIO`

---

## app_vitrine.py — Page publique

**Type** : Page 100% HTML statique rendue via `st.components.v1.html()` (height=4200).  
Aucune logique Python côté serveur — tout est du HTML/CSS/JS inline.

### Sections de la landing page

- **Nav** : Liens vers `#pain`, `#benefits`, `#expert`, `#offer`
- **Hero** : Accroche + 2 CTA + badges (rapidité, déductible, RGPD)
- **Scanner Demo** : Animation JS simulant un scan (SHA-256, xref, métadonnées Photoshop, écart budgétaire). Score de risque animé jusqu'à 94/100 via `requestAnimationFrame` sur 2.2 secondes
- **Pain points** (`#pain`) : 4 cartes — pertes min 3 000 €, délais d'expulsion 12–18 mois
- **Avantages** (`#benefits`) : Forensique métadonnées, SHA-256, cohérence budgétaire, rapport PDF. Processus en 3 étapes (Commande → Analyse → Rapport sous 24h)
- **Expertise** (`#expert`) : Exemple de rapport avec score, hash, xref, logiciel, écart budgétaire. Bio auteur Nolan
- **Offre** (`#offer`) : Prix 39 € TTC + boutons externes + formulaire de commande

### Formulaire de commande

Champs : `name`, `email`, `phone`, `doctype` (Fiche de paie / Avis d'imposition / Contrat de travail / Relevé bancaire / Autre), `message`, `gdpr`  
Soumission via `fetch()` POST JSON vers :  
```
FORMSPREE_ENDPOINT = "https://formspree.io/f/REMPLACE_PAR_TON_ID"
```
⚠️ **L'ID Formspree est encore un placeholder — à remplacer par l'ID réel.**

### Liens de paiement

- **LeBonCoin** : `https://leboncoin.fr/profil/3780fc14-e927-43d6-b826-40c02a3300c2`
- **Facebook** : `https://www.facebook.com/share/1KKBK1mfpV/`
- **Stripe** : `https://buy.stripe.com/test_3cI14ngjC4aga5L0fL0RG00` ⚠️ URL de test — à remplacer par l'URL live
- **PayPal** : `https://paypal.me/NolanBunet/39EUR`

### RGPD

Responsable de traitement : Nolan Bunet, bunetnolan@gmail.com, Sainte-Rose, Guadeloupe  
Conservation des données : 30 jours  
Droits : effacement par email

---

## app_expert.py — Interface d'analyse

### Accès

Protégé par `check_password()` :
- Lit `EXPERT_PASSWORD` depuis `os.getenv()` puis `st.secrets`
- Si absent → accès refusé définitivement
- `st.session_state["auth_ok"] = True` après succès

### Dataclasses (modèles de données)

```python
@dataclass
class AppSecrets:
    email_expediteur: str
    mot_de_passe_email: str

@dataclass
class PDFAnalysis:
    texte: str
    metadata: dict
    raw_bytes: bytes
    hash_sha256: str
    error: Optional[str]

@dataclass
class MathResult:
    est_scan: bool
    ecart: float
    calcul_theorique: float
    net_imposable_mensuel: float
    mois_cumules: int
    cumul_imposable: float
    fraude_math: bool

@dataclass
class ForensicResult:
    hash_sha256: str
    incremental_updates: int
    xref_anormal: bool
    fraude_meta: bool
    logiciels_detectes: list
    date_modifiee: bool
    javascript_suspect: bool
    fichiers_incorpores: bool
    annotations_suspectes: bool
    fonts_detectees: list
    score_risque_forensic: int

@dataclass
class Verdict:
    score_risque: int
    statut: str
    date_analyse: str
```

### Fonction `extract_pdf_content(fichier_pdf) -> PDFAnalysis`

- Lit les bytes complets du fichier uploadé
- Calcule `hashlib.sha256(pdf_bytes).hexdigest()`
- Extrait le texte de toutes les pages via `pdfplumber`
- Extrait les métadonnées : `Author`, `Creator`, `Producer`, `CreationDate`, `ModDate`

### Analyse mathématique (cohérence financière)

**`construire_math_result(texte)`** : Extrait via regex :
- `net_imposable_mensuel` : patterns `net\s+imposable`, `net\s+fiscal`, `montant\s+net\s+imposable`
- `cumul_imposable` : patterns `cumul\s+(?:net\s+)?imposable`, `net\s+imposable\s+annuel`, `total\s+imposable`
- `_to_float()` normalise les formats français (ex : "1 234,56" → 1234.56)

**`analyser_math(net_imposable_mensuel, nb_mois, cumul_saisi) -> MathResult`** :
- `calcul_theo = net_imposable_mensuel * nb_mois`
- Seuil de tolérance : `seuil = max(100.0, calcul_theo * 0.08)` (8%, minimum 100 €)
- `fraude_math = True` si `ecart > seuil` et les deux valeurs > 0

### Analyse forensique PDF

**`analyser_forensic(analysis: PDFAnalysis) -> ForensicResult`** :

**Détection xref/mises à jour incrémentielles (signature-aware) :**
```python
nb_eof = len(re.findall(rb"%%EOF", raw))
incremental_updates = max(nb_eof, 1)
nb_signatures = len(re.findall(rb"/ByteRange", raw))       # signature électronique
signature_detectee = nb_signatures > 0
updates_non_expliquees = max(incremental_updates - 1 - nb_signatures, 0)
xref_anormal = updates_non_expliquees > 0
```
Une signature électronique ajoute légitimement une sauvegarde incrémentielle par signature ;
ces mises à jour ne sont plus comptées comme anormales (évite de pénaliser les documents
officiels signés numériquement).

**Détection outils d'édition dans les métadonnées :**
```python
OUTILS_EDITION = ["photoshop", "gimp", "canva", "affinity", "indesign",
                  "illustrator", "inkscape", "paint", "pixelmator"]
PRODUCTEURS_LEGITIMES = ["adobe pdf library", "cegid", "sage", "dgfip",
                         "impots", ...]  # logiciels légitimes exclus
```
Vérifie les champs Créateur, Producteur, Auteur.

**Vérifications structurelles via pikepdf :**
- `root["/OpenAction"]` ou `root["/AA"]` ou `root["/Names"]["/JavaScript"]` → `javascript_suspect = True`
- `root["/Names"]["/EmbeddedFiles"]` → `fichiers_incorpores = True`
- Annotations par page avec `/Subtype` dans `("/FreeText", "/Redact")` → `annotations_suspectes = True`
  (`/Stamp` volontairement exclu : cachets/tampons de certification légitimes trop fréquents)
- Extraction des polices : `/Resources/Font/*/BaseFont` (strip du préfixe subset 6 majuscules)

**Fallback binaire** si pikepdf échoue :
- Vérifie `b"/JavaScript"`, `b"/JS"`, `b"/EmbeddedFile"` dans les raw bytes

**Score forensique pondéré :**
- xref_anormal : +30
- logiciels d'édition : +25
- date_modifiee : +5 (réduit ; 0 si signature électronique détectée)
- javascript : +20
- fichiers_incorpores : +15
- annotations_suspectes : +20
- Plafonné à 100

### Calcul du verdict

**`calculer_verdict(math, forensic) -> Verdict`** :
```python
score_global = int(0.6 * score_forensic + 0.4 * score_math)
# score_math = 45 si fraude_math else 0
```
- ≥ 70 → "ANOMALIES MAJEURES" (rouge)
- ≥ 40 → "ANOMALIES MODÉRÉES" (orange)
- < 40 → "AUCUNE ANOMALIE" (vert)

### Génération rapport PDF

**`build_report_pdf(verdict, forensic, math) -> bytes`** (via reportlab) :
- Couleurs : Navy `INK = #0F172A`, Amber `AMBER = #F59E0B`
- `NumberedCanvas` : header brandé + footer "Page X sur Y" sur chaque page
- `ScoreGauge(Flowable)` : jauge visuelle avec seuils à 40 et 70
- Référence rapport : `BS-{date}-{hash[:6]}`
- Nommage fichier : `BailSafe_ALERTE_*.pdf` / `BailSafe_ATTENTION_*.pdf` / `BailSafe_CONFORME_*.pdf`

**Sections du rapport :**
1. Tableau méta (référence, date, SHA-256 tronqué)
2. Jauge de score
3. Paragraphe de synthèse
4. Tableau des signaux forensiques
5. Tableau cohérence financière (si applicable)
6. Recommandations
7. Disclaimer légal

### Envoi email

**`envoyer_rapport(secrets, email_dest, pdf_bytes, filename)`** :
- SMTP Gmail : `smtp.gmail.com`, port 587, STARTTLS
- Message `MIMEMultipart` avec body texte + PDF en pièce jointe (base64)
- Sujet : `"Votre rapport BailSafe — Audit anti-fraude"`

### UI Streamlit — 3 onglets

**Tab 1 — Cohérence financière :**
- Détecte scan vs PDF numérique (texte < 20 chars → saisie manuelle)
- Auto-popule `net_auto`, `cumul_auto` depuis regex
- 3 colonnes `st.number_input`
- `st.metric` : cumul théorique, écart, seuil
- Sauvegarde `MathResult` dans `st.session_state["math_result"]`

**Tab 2 — Forensique PDF :**
- Statuts xref, date_modifiee, signaux de fraude (4 items avec icônes)
- Barre de progression `score_risque_forensic`
- Expandeur SHA-256 + liste des polices
- Métadonnées brutes en key-value

**Tab 3 — Verdict & Rapport :**
- Lit `math_result` et `forensic_result` depuis session state
- Bannière verdict colorée + barre de progression
- Bullets de recommandations
- `st.text_input` pour email client
- Bouton "Envoyer par email" → `envoyer_rapport()`
- Bouton `st.download_button` pour téléchargement direct PDF

### Caching session state

```python
if st.session_state["current_pdf_name"] != fichier_pdf.name:
    # relance extraction + forensic, clear math_result
    st.session_state["analysis"] = extract_pdf_content(fichier_pdf)
    st.session_state["forensic_result"] = analyser_forensic(...)
    st.session_state["math_result"] = None
```

---

## Configuration (secrets)

Trois variables requises, lues d'abord via `os.getenv()` puis `st.secrets` :

```toml
# .streamlit/secrets.toml
EMAIL_EXPEDITEUR   = "ton.email@gmail.com"
MOT_DE_PASSE_EMAIL = "xxxx xxxx xxxx xxxx"   # App Password Gmail
EXPERT_PASSWORD    = "mot_de_passe_expert"
```

Gmail App Password : Compte Google → Sécurité → Validation 2 étapes → Mots de passe des applications

---

## Limites connues

- Un document **imprimé puis re-scanné** après modification échappe à l'analyse (pas de métadonnées numériques)
- BailSafe fournit un **avis technique consultatif**, pas une garantie juridique
- Le formulaire de commande passe par Brevo (UE) via `netlify/functions/order.js` — nécessite
  `BREVO_API_KEY` et `BREVO_SENDER_EMAIL` configurés dans Netlify (voir `CLAUDE.md`), sans
  quoi le formulaire renvoie une erreur
- `index.html` est la seule vitrine du projet (l'ancienne version Streamlit `app_vitrine.py`,
  qui contenait un lien Stripe de test, a été supprimée du dépôt le 18 juillet 2026)
- Depuis le 18 juillet 2026, `app_expert.py` sait analyser un **dossier de plusieurs documents**
  (formules Sécurisé/Dossier Complet) avec cohérence croisée — voir le journal de session du
  18 juillet dans `CLAUDE.md` pour le détail des nouvelles fonctions (`analyser_dossier_croise`,
  `calculer_verdict_dossier`, `build_dossier_report_pdf`) ; cette section technique exhaustive
  ci-dessus documente encore uniquement le flux mono-document, à mettre à jour si besoin

---

## Commandes de lancement

```bash
# Installation
pip install -r requirements.txt

# Vitrine publique standalone : ouvrir index.html directement, ou déployer sur Netlify

# Interface expert
streamlit run app_expert.py --server.port 8502
```

## Sécurisation accès expert

- **Streamlit Cloud** : Settings → Sharing → "Only specific people"
- **Cloudflare Access** (gratuit, recommandé) : Zero Trust → Applications → protège l'URL expert

---

## Points d'évolution identifiés

- Finaliser le déploiement Render et renseigner son URL dans `BAILSAFE_CONTEXTE.md`
- Possibilité d'intégrer n8n pour automatiser la réception + envoi du rapport
- Potentiel chatbot/agent d'accueil sur la vitrine
- Export rapport en DOCX en plus du PDF
