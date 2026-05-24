# AI Security Lab - System Design Corrections (1-by-1)

## Step 0: Baseline review

- [x] Read project files and explain current behavior

## Step 1: Fix time handling bug (current request timestamp ignored)

- [ ] Update `server.js` so in-memory `eventHistory` uses request-body `timestamp` (parsed) instead of `new Date()`.
- [ ] Ensure detection window uses the same timestamp field.
- [ ] Add validation/fallback when timestamp is missing/invalid.
- [ ] Update any related logic so SQLite and in-memory stay consistent.

## Step 2: Normalize event types

- [ ] Introduce canonical event schema + mapping from both agents.

## Step 3: Persist alerts + dedupe w/ expiry

- [ ] Create SQLite `alerts` table; implement time-window dedupe and alert lifecycle.

## Step 4: Move AI calls out of ingestion path

- [ ] Add simple in-process queue/worker for AI enrichment.

## Step 5: Constrain AI prompts + sanitize UI rendering

- [ ] Limit alerts included in `/ai/summary`.
- [ ] Use safe DOM rendering instead of innerHTML for LLM output.
