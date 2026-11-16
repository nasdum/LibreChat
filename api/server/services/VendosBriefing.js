const mongoose = require("mongoose");
const { logger } = require("@librechat/data-schemas");
const { GenerationJobManager } = require("@librechat/api");
const { createVendosBriefing } = require("@librechat/api/vendos");
const { getUserPluginAuthValue } = require("./PluginService");
const VENDOS_OWNER = process.env.VENDOS_BRIEFING_OWNER_ID;
const VENDOS_THREAD = process.env.VENDOS_BRIEFING_THREAD_ID;
const VENDOS_OWNER_EMAIL = process.env.VENDOS_BRIEFING_OWNER_EMAIL;
const VENDOS_MCP_URL = process.env.VENDOS_BRIEFING_MCP_URL;

let service;

function initializeVendosBriefing(appConfig) {
  const configured = appConfig?.modelSpecs?.list?.find(
    (item) => item.name === "vendos-pilot",
  )?.preset;
  if (
    service ||
    !VENDOS_OWNER ||
    !VENDOS_THREAD ||
    !VENDOS_OWNER_EMAIL ||
    !VENDOS_MCP_URL ||
    configured?.endpoint !== "VENDOS pilot" ||
    !configured?.model ||
    !mongoose.connection.db
  ) {
    return;
  }
  const { endpoint, model, endpointType, agent_id, promptPrefix } = configured;
  service = createVendosBriefing({
    db: mongoose.connection.db,
    ownerId: VENDOS_OWNER,
    threadId: VENDOS_THREAD,
    ownerEmail: VENDOS_OWNER_EMAIL,
    mcpUrl: VENDOS_MCP_URL,
    preset: { endpoint, model, endpointType, agent_id, promptPrefix },
    getKey: () =>
      getUserPluginAuthValue(
        VENDOS_OWNER,
        "VENDOS_PILOT_KEY",
        false,
        "mcp_vendos_pilot",
      ),
    getOwner: () =>
      mongoose.connection.db
        .collection("users")
        .findOne(
          { _id: new mongoose.Types.ObjectId(VENDOS_OWNER) },
          { projection: { email: 1, tenantId: 1 } },
        ),
    isBusy: async () => {
      const job = await GenerationJobManager.getJob(VENDOS_THREAD);
      return (
        !!job &&
        !["completed", "failed", "aborted", "cancelled"].includes(job.status)
      );
    },
    log: (event) => logger.warn(`[VENDOS briefing] ${event}`),
  });
  service.start();
}

async function handleVendosMessage(req, protocolVersion) {
  try {
    if (!service) {
      const matches =
        req.user?.id === VENDOS_OWNER &&
        req.body?.conversationId === VENDOS_THREAD &&
        /^(schvaluji|souhlasím|souhlasim)\b/i.test(
          req.body?.text?.trim() ?? "",
        );
      return matches
        ? {
            handled: true,
            statusCode: 503,
            error: "Schvalování se právě připravuje. Nic se neprovedlo.",
          }
        : { handled: false };
    }
    return await service.handle({
      userId: req.user.id,
      tenantId: req.user.tenantId,
      body: req.body,
      protocolVersion,
    });
  } catch {
    logger.warn(
      "[VENDOS briefing] Request could not be settled; no fallback model approval",
    );
    return {
      handled: true,
      statusCode: 503,
      error:
        "Přijetí schválení se nepodařilo ověřit. Vyčkejte na stav v chatu; neodesílejte změny opakovaně.",
    };
  }
}

module.exports = { initializeVendosBriefing, handleVendosMessage };
