const { createMemoryStores } = require('./memory');

// Redis when REDIS_URL is set, memory otherwise.
function createStores(config, { now } = {}) {
  const opts = {
    sessionTtlSeconds: config.sessionTtlSeconds,
    stepSeconds: config.otpStepSeconds,
    attemptsPerWindow: config.attemptsPerWindow,
    ipAttemptsPerMinute: config.ipAttemptsPerMinute,
    tokenTtlSeconds: config.tokenTtlSeconds,
    maxTokensPerDevice: config.maxTokensPerDevice,
    ...(now ? { now } : {}),
  };
  if (config.redisUrl) {
    const { createRedisStores } = require('./redis');
    return createRedisStores({ redisUrl: config.redisUrl, ...opts });
  }
  return createMemoryStores(opts);
}

module.exports = { createStores };
