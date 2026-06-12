---
name: memstart
description: Checkpoint durable memory before a session ends or restarts — update auto-memory files, write/refresh the repo handoff, commit. Use when the user says "memstart", "save memory", "checkpoint before restart", or before a planned VM/session restart.
---

# memstart — durable memory checkpoint

Goal: a fresh session (possibly on a different machine) can resume the work cold,
from committed artifacts alone. Trust git + repo files over conversation memory.

Steps:

1. **Repo handoff** — write or update `memory/<today>-handoff.md` in the repo:
   - branch + HEAD commit, working-tree state (anything deliberately uncommitted and WHY)
   - in-flight background work: what was running, log paths, whether it dies with the
     session, and the exact relaunch commands
   - slice/task state: what's done (with commit hashes), what's NEXT (first action verbatim)
   - environment gotchas discovered this session (paths, flags, wedges, workarounds)
   - the standing gate/test commands for the current work
2. **Auto-memory** (`~/.claude/projects/<project>/memory/`):
   - update the current chapter/arc state file: status, key commits, open questions,
     pointer to the repo handoff (the handoff holds detail; memory holds pointers +
     non-derivable facts)
   - update any environment/feedback memory files with NEW durable lessons only
   - refresh `MEMORY.md` index hooks (one line per file; no content in the index)
3. **Commit** the repo handoff (and any other deliberate working-tree state) with a
   message saying it is a restart checkpoint.
4. **Report**: stopping-point summary — what's committed, what dies on restart, the
   first three actions for the next session, and how to resume (fresh session reading
   the handoff is preferred over --continue when context is nearly spent).

Rules:
- Never store in memory what the repo already records (code structure, git history).
- Convert relative dates to absolute. Link related memory files with [[name]].
- If background jobs are running, say explicitly which results will be lost and how
  to regenerate them.
