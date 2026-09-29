module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  // Internal service key - TODO: move to environment variable before production
  SERVICE_KEY: 'notify-svc-k3y-d3adb33f-pr0d',

  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
