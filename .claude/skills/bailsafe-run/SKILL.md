---
name: bailsafe-run
description: Launch the BailSafe expert Streamlit app locally for testing (app_expert.py). Not for the public vitrine, which is the standalone index.html deployed on Netlify.
---

Launch `app_expert.py` locally with Streamlit so Nolan can test the forensic analysis
interface before deploying to Render.

Steps:
1. Check Python is actually usable (not just the Windows Store stub):
   `Get-Command python | Select-Object Source` — if the source path contains `WindowsApps`,
   Python isn't really installed. Tell Nolan and stop; don't try to run Streamlit against
   the stub.
2. Check `streamlit` is installed: `python -m streamlit --version`. If missing, offer to run
   `pip install -r requirements.txt` first (ask before installing packages).
3. Run: `streamlit run app_expert.py --server.port 8502`
4. This is a long-running/blocking process — run it and tell Nolan the local URL
   (usually `http://localhost:8502`) rather than waiting for it to exit.

Note: `index.html` (the public vitrine) doesn't need this — it's static and already live on
Netlify. This skill is only for testing the password-protected expert analysis tool locally.
