/**
 * Enkrypt AI Guardrails for Vercel AI SDK
 *
 * Protect your AI applications with Enkrypt AI Guardrails.
 * This package provides middleware for Vercel AI SDK that enables:
 *
 * - Prompt injection detection
 * - PII/secrets detection
 * - Toxicity filtering
 * - Content moderation
 * - Tool call protection
 *
 * @packageDocumentation
 */

// Core guardrails module
export {
  // Configuration
  loadConfig,
  reloadConfig,
  getDefaultConfig,
  isHookEnabled,
  getHookBlockList,
  getHookGuardrailName,

  // API client
  checkWithEnkryptApi,
  parseEnkryptResponse,
  formatViolationMessage,

  // Tool utilities
  isSensitiveTool,

  // Logging
  logEvent,
  logSecurityAlert,
  flushLogs,

  // Metrics
  getMetrics,
  resetMetrics,

  // Exceptions
  GuardrailsViolationError,

  // Types
  type EnkryptApiConfig,
  type HookPolicy,
  type GuardrailsConfig,
  type Violation,
  type CheckResult,
  type LogEntry,
  type HookMetrics,
  type DetectorType,
  DETECTOR_TYPES,
} from './enkrypt-guardrails';

// Middleware
export {
  // Main middleware factory
  createEnkryptMiddleware,

  // Convenience factories
  createBlockingMiddleware,
  createAuditMiddleware,
  createInputOnlyMiddleware,
  createOutputOnlyMiddleware,

  // Tool protection
  wrapToolWithGuardrails,

  // Step callbacks
  createPrepareStepWithGuardrails,
  createOnStepFinishWithGuardrails,

  // Types
  type EnkryptMiddlewareOptions,
  type LanguageModelV3Middleware,
  type LanguageModelCallOptions,
  type GenerateResult,
  type StreamResult,
} from './enkrypt-middleware';
