---
name: session-journal
description: Append a session journal entry to CLAUDE.md summarizing what changed in this BailSafe session, following the project's established format.
---

Add a new entry to the "## Journal de session" section of `CLAUDE.md` in this project.

Format to follow (match the existing entries already in that file):

```
### <date en français, ex: 4 juillet 2026>

- <bullet courte par changement significatif — quoi, pas comment>
- ...

**TODO manuels restants (hors de portée de l'agent) :**
- <action que seul Nolan peut faire — compte externe, mot de passe, décision produit>
```

Rules:
- Keep bullets short (one or two lines each) — technical detail belongs in code comments or
  the other context files (`BAILSAFE_CONTEXTE.md`, `NOLAN_BAILSAFE_contexte.md`), not here.
- Only include what actually changed in the current session — don't restate old entries.
- If today's date already has a "###" heading in the journal (same-day follow-up session),
  append bullets to that existing section instead of creating a duplicate heading.
- Carry forward any still-unresolved items from the previous "TODO manuels restants" list,
  and drop ones that got resolved this session.
- If nothing substantial changed this session (pure Q&A, no file edits), say so instead of
  inventing an entry.
