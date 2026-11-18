const { enforceVendosRestrictedConfig, isVendosRestrictedIdentity } = require('@librechat/api/vendos');
const { logger } = require('@librechat/data-schemas');
const { getAppConfigOptionsFromUser } = require('@librechat/api');
const { getAppConfig } = require('~/server/services/Config');

const configMiddleware = async (req, res, next) => {
  try {
    req.config = await getAppConfig(getAppConfigOptionsFromUser(req.user));

    enforceVendosRestrictedConfig(req);
    next();
  } catch (error) {
    if (isVendosRestrictedIdentity(req.user)) return res.status(403).json({ error: 'VENDOS_ACCESS_RESTRICTED' });
    logger.error('Config middleware error:', {
      error: error.message,
      userRole: req.user?.role,
      path: req.path,
    });

    try {
      req.config = await getAppConfig({ tenantId: req.user?.tenantId });
      next();
    } catch (fallbackError) {
      logger.error('Fallback config middleware error:', fallbackError);
      next(fallbackError);
    }
  }
};

module.exports = configMiddleware;
