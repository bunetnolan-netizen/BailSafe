# 🛡️ BailSafe — Audit Anti-Fraude Locatif

Outil d'audit documentaire pour bailleurs : analyse forensique PDF, cohérence financière, rapport PDF transmissible.

## Structure du projet

```
bailsafe/
├── app_vitrine.py          ← Page publique (vitrine + toute la logique)
├── app_expert.py           ← Interface d'analyse (URL séparée)
├── requirements.txt
├── .gitignore
└── .streamlit/
    ├── secrets.toml        ← À CRÉER localement (jamais commité)
    └── secrets.toml.example
```

## Installation

```bash
pip install -r requirements.txt
```

## Configuration des secrets

Copie `.streamlit/secrets.toml.example` en `.streamlit/secrets.toml` et remplis :

```toml
EMAIL_EXPEDITEUR   = "ton.email@gmail.com"
MOT_DE_PASSE_EMAIL = "xxxx xxxx xxxx xxxx"
```

> **App Password Gmail** : Compte Google → Sécurité → Validation en 2 étapes → Mots de passe des applications

## Lancement

```bash
# Vitrine publique
streamlit run app_vitrine.py

# Interface expert (port séparé)
streamlit run app_expert.py --server.port 8502
```

## Sécuriser l'accès expert

**Streamlit Cloud** : Settings → Sharing → "Only specific people"

**Cloudflare Access** (gratuit, recommandé) : Zero Trust → Applications → protège l'URL expert

## Ce que détecte BailSafe

- Hash SHA-256 (intégrité du fichier)
- Sections xref multiples (PDF remanié)
- Outils d'édition graphique dans les métadonnées
- JavaScript embarqué
- Fichiers incorporés suspects
- Écart budgétaire avec seuil proportionnel au salaire

## Limites

Un document imprimé puis re-scanné après modification échappe à l'analyse. BailSafe fournit un avis technique consultatif, pas une garantie juridique.

---

*Par Nolan Bunet — bunetnolan@gmail.com*
