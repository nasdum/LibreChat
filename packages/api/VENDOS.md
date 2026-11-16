# VENDOS briefing bridge

The bridge is deliberately scoped to the existing VENDOS owner and one private conversation. It uses the owner's existing per-user MCP credential and the internal notebook relay; no new credential or public endpoint is introduced.

The bridge is opt-in. Set `VENDOS_BRIEFING_OWNER_ID`, `VENDOS_BRIEFING_OWNER_EMAIL`, `VENDOS_BRIEFING_THREAD_ID`, and `VENDOS_BRIEFING_MCP_URL` in the private deployment environment. Do not commit these deployment values. Missing configuration leaves the bridge disabled.

`src/vendos.ts` contains the delivery journal, deterministic Czech selection parser, authenticated-message attestation, and bounded recovery. The existing native tool-approval path is unchanged. The API bootstrap supplies database, credentials, the existing VENDOS preset, and generation-busy checks through `api/server/services/VendosBriefing.js`.

Only a new authenticated user request in the fixed conversation can create an approval journal entry. The controller verifies the current delivered immutable offer, exact parent and stored message body, expiration, and every selected action before recording the user message and signing its receipt. Edited, imported, quoted, regenerated, conditional, cross-account, and outdated messages cannot authorize execution. The service never exposes signing to model tools. Actual execution and provider-side idempotency remain in the notebook's approved-plan worker.

Delivery IDs and user-message IDs are durable idempotency keys. A MongoDB lease serializes delivery and authorization across process instances. Lost acknowledgement responses are retried with the same identity; authorization retries are bounded. Local accepted receipts and unacknowledged deliveries recover after restart. A failed delivery does not block later independent deliveries.

The 30-second bridge poll does not call a model. The notebook owns the Monday 08:30 Europe/Prague schedule and sends content through `briefing_poll`. `briefing_ack` is signed only after durable storage. The full action summary must be present in the visible briefing body before the server delivers an executable offer.

Run `npm run test:vendos --workspace=@librechat/api` after the normal workspace install. Tests use a real isolated MongoDB via the repository's mongodb-memory-server dependency, with only external notebook HTTP replaced. They exercise selection, delivery, message provenance, replay, partial transport failure, restart, and concurrency. No production keys or data are required.

Builds include the independent `@librechat/api/vendos` entry. Production can roll back the API image without changing marketing data; pending approvals remain in the notebook and must be reconciled, not replayed as new operations. Collections `vendos_briefing_deliveries`, `vendos_briefing_approvals`, and `vendos_briefing_leases` contain private service bookkeeping and must not be exposed to model tools.

## Content-only strategy decisions

`src/vendos/drafts.ts` implements the separate content decision protocol. An explicitly classified notebook offer has `decision_type: "draft"`, its original immutable JSON `payload`, and the matching `bundle_hash`. Every item names the exact job, revision, stable key, raw stored draft SHA256 and raw stored review SHA256. All items must be advisory: `executable: false` and explicit null execution-plan fields. Missing metadata on older deliveries is not inferred or repaired; those offers remain legacy and require a new display. The notebook independently rechecks the current reviewed version and both hashes in its atomic feedback transaction.

The exact content phrases are `Souhlasím se všemi body` or `Souhlasím s obsahem strategie v4, body 1 a 3`, with an optional final period. The protocol applies only NFC, ASCII-space trim and lowercase; the signed text hash always uses the original message. Mixed execution instructions, quoted/edited/imported messages, wrong revisions and ambiguous selections are rejected without a model fallback. Advisory rejection messages never suggest execution wording.

The adapter first persists the authenticated owner's new message and rereads it before signing `kind: "vendos_draft_decision"` for `briefing_approve_draft`. The source must be the latest acknowledged briefing in the fixed private conversation. A bounded persisted ancestor chain may contain that offer's acknowledged notebook details and earlier accepted content decisions with their server-owned confirmations. Arbitrary model replies and unrelated messages are not trusted ancestors. This permits separate subset decisions without treating assistant text as authorization.

Content bookkeeping uses the additional private collection `vendos_briefing_draft_decisions`, with the owner message UUID as `_id`. MongoDB creates this additive collection on first use; no existing documents, credentials, indexes or approval types require conversion. Captured decisions cannot cross the execution/content journals. Content consent never queues `briefing_approve`, `execute_approved_change`, publication, customer mail, Ads mutations or business-task changes.

A successful content confirmation is saved only after the notebook returns `draft_decision_saved`, `decision: "approve_draft"`, a decision ID and `execution_allowed: false`. A timeout is explicitly unconfirmed. Recovery retries the same stored signed bytes and message UUID at most three times within five minutes, so restart cannot turn an older or edited message into new authority. An unresolved outcome goes to attention; the original notebook audit must be checked before requesting a replacement decision.

The bridge uses the actual generation-job terminal states `complete`, `error` and `aborted`. Retained terminal jobs do not block delivery or content decisions after their terminal persistence completes; `metadata.terminalPersistencePending: true`, running, `requires_action` and unknown states do. Real Mongo integration tests cover these states, timestamp drift, ancestry, subset decisions, exact Python/TypeScript receipt fixtures, ambiguous failures and the existing execution path.
