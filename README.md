# 🛡️ BailSafe — Audit Anti-Fraude Locatif

Outil d'audit documentaire pour bailleurs : analyse forensique PDF, cohérence financière, rapport PDF transmissible.

## Structure du projet

```
bailsafe/
├── index.html              ← Vitrine standalone (Netlify)
├── app_expert.py           ← Interface d'analyse experte (Streamlit, Render)
├── netlify/functions/      ← Fonctions serverless Netlify (commande, emails)
├── tests/                  ← Tests pytest (27 tests)
├── requirements.txt
├── netlify.toml
├── .gitignore
└── secrets.toml.example
```

## Installation

```bash
pip install -r requirements.txt
```

## Configuration des secrets

Copie `secrets.toml.example` en `.streamlit/secrets.toml` et remplis :

```toml
EMAIL_EXPEDITEUR   = "ton.email@gmail.com"
MOT_DE_PASSE_EMAIL = "xxxx xxxx xxxx xxxx"   # App Password Gmail
EXPERT_PASSWORD    = "mot_de_passe_choisi_par_toi"
```

> **App Password Gmail** : Compte Google → Sécurité → Validation en 2 étapes → Mots de passe des applications

## Lancement

```bash
# Interface expert
streamlit run app_expert.py --server.port 8502

# Tests
python -m pytest tests/ -v
```

## Déploiement

- **Vitrine** : https://bail-safe.netlify.app/ (auto-déploiement depuis GitHub)
- **App Expert** : https://bailsafe-expert.onrender.com/ (auto-déploiement depuis GitHub)
- **Fonctions** : Netlify Functions (`netlify/functions/order.js`)

Variables d'environnement requises sur Netlify : `BREVO_API_KEY`, `BREVO_SENDER_EMAIL`.
Variables d'environnement requises sur Render : `EXPERT_PASSWORD`, `EMAIL_EXPEDITEUR`, `MOT_DE_PASSE_EMAIL`.

## Ce que détecte BailSafe

- Hash SHA-256 (intégrité du fichier)
- Sections xref multiples (PDF remanié)
- Outils d'édition graphique dans les métadonnées
- JavaScript embarqué
- Fichiers incorporés suspects
- Écart budgétaire avec seuil proportionnel au salaire
- Analyse croisée multi-documents (formules Sécurisé/Dossier Complet)

## Limites

Un document imprimé puis re-scanné après modification échappe à l'analyse. BailSafe fournit un avis technique consultatif, pas une garantie juridique.

## Tarifs

| Formule | Prix TTC | Documents |
|---|---|---|
| Essentiel | 59 € | 1 document |
| Sécurisé | 129 € | Jusqu'à 2 documents + cohérence croisée |
| Dossier Complet | 229 € | Jusqu'à 4 documents + prioritaire |

---

*Par Nolan Bunet — bunetnolan@gmail.com — Sainte-Rose, Guadeloupe*
