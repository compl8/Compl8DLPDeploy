---
name: contstart
description: Resume a work thread at session start — load memory pointers, read the latest repo handoff, verify environment, report status, and continue from the documented next step. Use when the user says "contstart" or "constart", "pick up the thread", "resume where we left off", or at the first message of a continuation session.
---

# contstart — continuation start

Goal: full continuity from committed artifacts, then KEEP WORKING — do not make the
user re-explain anything.

Steps:

1. **Load the trail**:
   - auto-memory `MEMORY.md` is already in context — follow its chapter/arc state
     pointer(s)
   - read the NEWEST `memory/*-handoff.md` in the repo (the authoritative state)
   - `git log --oneline -10` + `git status` — reconcile against the handoff; trust
     git when they disagree (the handoff may predate late commits)
2. **Verify environment** before launching anything heavy:
   - the handoff's environment checklist (e.g. VM resources after an upgrade:
     `$env:NUMBER_OF_PROCESSORS`, total RAM)
   - background work that died with the old session: check its logs; relaunch per
     the handoff's commands if results are missing
3. **Report** (concise): where the thread stands, what survived/died, what the next
   actions are — then START the first one without waiting, unless it is destructive
   or the handoff flags an open decision for the user.
4. If anything contradicts the handoff (failed gates, missing files, diverged
   branch), surface it FIRST and resolve before continuing the plan.

Rules:
- Fresh-session constart beats --continue when the prior session ended near its
  context limit; say so if the user asks.
- Do not re-litigate decisions recorded in the handoff/design docs; evolve them
  only on new evidence and note the change in the next memstart.
