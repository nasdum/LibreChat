# VENDOS briefing bridge

The bridge is deliberately scoped to the existing VENDOS owner and one private conversation. It uses the owner's existing per-user MCP credential and the internal notebook relay; no new credential or public endpoint is introduced.

The bridge is opt-in. Set `VENDOS_BRIEFING_OWNER_ID`, `VENDOS_BRIEFING_OWNER_EMAIL`, `VENDOS_BRIEFING_THREAD_ID`, and `VENDOS_BRIEFING_MCP_URL` in the private deployment environment. Do not commit these deployment values. Missing configuration leaves the bridge disabled.

`src/vendos.ts` contains the delivery journal, deterministic Czech selection parser, authenticated-message attestation, and bounded recovery. The existing native tool-approval path is unchanged. The API bootstrap supplies database, credentials, the existing VENDOS preset, and generation-busy checks through `api/server/services/VendosBriefing.js`.

Only a new authenticated user request in the fixed conversation can create an approval journal entry. The controller verifies the current delivered immutable offer, exact parent and stored message body, expiration, and every selected action before recording the user message and signing its receipt. Edited, imported, quoted, regenerated, conditional, cross-account, and outdated messages cannot authorize execution. The service never exposes signing to model tools. Actual execution and provider-side idempotency remain in the notebook's approved-plan worker.

Delivery IDs and user-message IDs are durable idempotency keys. A MongoDB lease serializes delivery and authorization across process instances. Lost acknowledgement responses are retried with the same identity; authorization retries are bounded. Local accepted receipts and unacknowledged deliveries recover after restart. A failed delivery does not block later independent deliveries.

The 30-second bridge poll does not call a model. The notebook owns the Monday 08:30 Europe/Prague schedule and sends content through `briefing_poll`. `briefing_ack` is signed only after durable storage. The full action summary must be present in the visible briefing body before the server delivers an executable offer.

Run `npm run test:vendos --workspace=@librechat/api` after the normal workspace install. Tests use a real isolated MongoDB via the repository's mongodb-memory-server dependency, with only external notebook HTTP replaced. They exercise selection, delivery, message provenance, replay, partial transport failure, restart, and concurrency. No production keys or data are required.

Builds include the independent `@librechat/api/vendos` entry. Production can roll back the API image without changing marketing data; pending approvals remain in the notebook and must be reconciled, not replayed as new operations. Collections `vendos_briefing_deliveries`, `vendos_briefing_approvals`, and `vendos_briefing_leases` contain private service bookkeeping and must not be exposed to model tools.
