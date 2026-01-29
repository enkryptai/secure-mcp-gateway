/**
 * Enkrypt AI Guardrails Core Module for Vercel AI SDK
 *
 * This module provides the core functionality for integrating Enkrypt AI
 * Guardrails with Vercel AI SDK applications.
 *
 * Features:
 * - HTTP client with retry logic
 * - Response parsing and violation detection
 * - Logging and metrics collection
 * - Configuration management
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ============================================================================
// TYPES
// ============================================================================

export interface EnkryptApiConfig {
  url: string;
  api_key: string;
  ssl_verify: boolean;
  timeout: number;
  fail_silently: boolean;
}

export interface HookPolicy {
  enabled: boolean;
  guardrail_name: string;
  block: string[];
}

export interface GuardrailsConfig {
  enkrypt_api: EnkryptApiConfig;
  transformParams: HookPolicy;
  wrapGenerate: HookPolicy;
  wrapStream: HookPolicy;
  prepareStep: HookPolicy;
  onStepFinish: HookPolicy;
  onToolCall: HookPolicy;
  sensitive_tools: string[];
}

export interface Violation {
  detector: string;
  score: number;
  threshold: number;
  detected: boolean;
  details?: Record<string, unknown>;
}

export interface CheckResult {
  shouldBlock: boolean;
  violations: Violation[];
  rawResult: Record<string, unknown> | null;
}

export interface LogEntry {
  timestamp: string;
  hook: string;
  event: string;
  data: Record<string, unknown>;
}

export interface HookMetrics {
  totalCalls: number;
  blocked: number;
  allowed: number;
  errors: number;
  totalLatencyMs: number;
}

// ============================================================================
// CONSTANTS
// ============================================================================

const DEFAULT_API_URL = 'https://api.enkryptai.com/guardrails/policy/detect';
const DEFAULT_TIMEOUT = 15000; // 15 seconds
const LOG_DIR = path.join(os.homedir(), 'vercel-ai-sdk', 'guardrails_logs');

// Detectors that Enkrypt API can return
export const DETECTOR_TYPES = [
  'injection_attack',
  'pii',
  'toxicity',
  'nsfw',
  'bias',
  'sponge_attack',
  'keyword_detector',
  'topic_detector',
  'policy_violation',
] as const;

export type DetectorType = typeof DETECTOR_TYPES[number];

// ============================================================================
// CONFIGURATION
// ============================================================================

let config: GuardrailsConfig | null = null;

/**
 * Load configuration from file or environment
 */
export function loadConfig(configPath?: string): GuardrailsConfig {
  if (config) return config;

  const possiblePaths = [
    configPath,
    process.env.ENKRYPT_GUARDRAILS_CONFIG,
    path.join(process.cwd(), 'guardrails-config.json'),
    path.join(__dirname, '..', 'guardrails-config.json'),
  ].filter(Boolean) as string[];

  for (const p of possiblePaths) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf-8');
        config = JSON.parse(content) as GuardrailsConfig;

        // Override API key from environment if set
        if (process.env.ENKRYPT_API_KEY) {
          config.enkrypt_api.api_key = process.env.ENKRYPT_API_KEY;
        }

        return config;
      }
    } catch {
      // Continue to next path
    }
  }

  // Return default config if no file found
  config = getDefaultConfig();
  return config;
}

/**
 * Get default configuration
 */
export function getDefaultConfig(): GuardrailsConfig {
  return {
    enkrypt_api: {
      url: process.env.ENKRYPT_API_URL || DEFAULT_API_URL,
      api_key: process.env.ENKRYPT_API_KEY || '',
      ssl_verify: true,
      timeout: DEFAULT_TIMEOUT,
      fail_silently: true,
    },
    transformParams: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['injection_attack', 'pii', 'toxicity', 'nsfw'],
    },
    wrapGenerate: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['pii', 'toxicity', 'nsfw'],
    },
    wrapStream: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['pii', 'toxicity', 'nsfw'],
    },
    prepareStep: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['injection_attack', 'pii'],
    },
    onStepFinish: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['pii', 'toxicity'],
    },
    onToolCall: {
      enabled: true,
      guardrail_name: 'Sample Airline Guardrail',
      block: ['injection_attack', 'pii'],
    },
    sensitive_tools: [
      'execute_sql',
      'run_command',
      'shell_*',
      'bash',
      'delete_*',
      'remove_*',
      'write_file',
      'send_email',
      'http_request',
    ],
  };
}

/**
 * Reload configuration from disk
 */
export function reloadConfig(configPath?: string): GuardrailsConfig {
  config = null;
  return loadConfig(configPath);
}

/**
 * Check if a hook is enabled
 */
export function isHookEnabled(hookName: keyof GuardrailsConfig): boolean {
  const cfg = loadConfig();
  const hookConfig = cfg[hookName];
  if (typeof hookConfig === 'object' && 'enabled' in hookConfig) {
    return hookConfig.enabled;
  }
  return false;
}

/**
 * Get block list for a hook
 */
export function getHookBlockList(hookName: keyof GuardrailsConfig): string[] {
  const cfg = loadConfig();
  const hookConfig = cfg[hookName];
  if (typeof hookConfig === 'object' && 'block' in hookConfig) {
    return hookConfig.block;
  }
  return [];
}

/**
 * Get guardrail name for a hook
 */
export function getHookGuardrailName(hookName: keyof GuardrailsConfig): string {
  const cfg = loadConfig();
  const hookConfig = cfg[hookName];
  if (typeof hookConfig === 'object' && 'guardrail_name' in hookConfig) {
    return hookConfig.guardrail_name;
  }
  return 'Default Policy';
}

// ============================================================================
// API CLIENT
// ============================================================================

/**
 * Check content with Enkrypt AI API
 */
export async function checkWithEnkryptApi(
  text: string,
  hookName: string = 'transformParams'
): Promise<CheckResult> {
  const cfg = loadConfig();
  const startTime = Date.now();

  // Skip if no API key
  if (!cfg.enkrypt_api.api_key) {
    logEvent(hookName, 'api_skipped', { reason: 'no_api_key' });
    return { shouldBlock: false, violations: [], rawResult: null };
  }

  // Skip empty text
  if (!text || !text.trim()) {
    return { shouldBlock: false, violations: [], rawResult: null };
  }

  const hookConfig = cfg[hookName as keyof GuardrailsConfig] as HookPolicy | undefined;
  const guardrailName = hookConfig?.guardrail_name || 'Default Policy';
  const blockList = hookConfig?.block || [];

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), cfg.enkrypt_api.timeout);

    const response = await fetch(cfg.enkrypt_api.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': cfg.enkrypt_api.api_key,
        'X-Enkrypt-Policy': guardrailName,
        'X-Enkrypt-Source-Name': 'vercel-ai-sdk',
        'X-Enkrypt-Source-Event': hookName,
      },
      body: JSON.stringify({
        text: text,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      logEvent(hookName, 'api_error', {
        status: response.status,
        error: errorText,
      });

      if (cfg.enkrypt_api.fail_silently) {
        return { shouldBlock: false, violations: [], rawResult: null };
      }
      throw new Error(`Enkrypt API error: ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    const latency = Date.now() - startTime;

    // Log API response
    logApiResponse(hookName, result, latency);

    // Parse violations
    const { shouldBlock, violations } = parseEnkryptResponse(result, blockList);

    // Update metrics
    updateMetrics(hookName, shouldBlock, latency);

    return { shouldBlock, violations, rawResult: result };
  } catch (error) {
    const latency = Date.now() - startTime;
    logEvent(hookName, 'api_exception', {
      error: error instanceof Error ? error.message : String(error),
      latency,
    });

    updateMetrics(hookName, false, latency, true);

    if (cfg.enkrypt_api.fail_silently) {
      return { shouldBlock: false, violations: [], rawResult: null };
    }
    throw error;
  }
}

/**
 * Parse Enkrypt API response and determine violations
 *
 * API Response Format:
 * {
 *   "summary": {
 *     "injection_attack": 1,      // 1 = detected, 0 = not detected
 *     "pii": 1,
 *     "toxicity": ["toxicity"],   // can be a list
 *     ...
 *   },
 *   "details": {
 *     "injection_attack": { "safe": "0.01", "attack": "0.99", ... },
 *     ...
 *   }
 * }
 */
export function parseEnkryptResponse(
  result: Record<string, unknown>,
  blockList: string[]
): { shouldBlock: boolean; violations: Violation[] } {
  const violations: Violation[] = [];
  let shouldBlock = false;

  const summary = result.summary as Record<string, unknown> | undefined;
  const details = result.details as Record<string, unknown> | undefined;

  if (!summary) {
    return { shouldBlock, violations };
  }

  // Map summary keys to detector names
  const detectorMapping: Record<string, string> = {
    'nsfw': 'nsfw',
    'toxicity': 'toxicity',
    'pii': 'pii',
    'injection_attack': 'injection_attack',
    'keyword_detected': 'keyword_detector',
    'policy_violation': 'policy_violation',
    'bias': 'bias',
    'sponge_attack': 'sponge_attack',
    'on_topic': 'topic_detector',
  };

  for (const [summaryKey, detectorName] of Object.entries(detectorMapping)) {
    const summaryValue = summary[summaryKey];

    // Check if this detector triggered
    let isDetected = false;
    if (typeof summaryValue === 'number' && summaryValue === 1) {
      isDetected = true;
    } else if (Array.isArray(summaryValue) && summaryValue.length > 0) {
      isDetected = true;
    } else if (typeof summaryValue === 'boolean' && summaryValue) {
      isDetected = true;
    }

    // Special case: on_topic=0 means OFF topic (violation), on_topic=1 means ON topic (ok)
    if (summaryKey === 'on_topic') {
      isDetected = typeof summaryValue === 'number' && summaryValue === 0;
    }

    if (isDetected) {
      // Get details for this detector
      const detectorDetails = (details?.[detectorName] || details?.[summaryKey] || {}) as Record<string, unknown>;

      // Extract score if available (e.g., injection_attack has "attack" score)
      let score = 0;
      if (typeof detectorDetails.attack === 'string') {
        score = parseFloat(detectorDetails.attack);
      } else if (typeof detectorDetails.score === 'number') {
        score = detectorDetails.score;
      }

      const violation: Violation = {
        detector: detectorName,
        score,
        threshold: 0.5,
        detected: true,
        details: detectorDetails,
      };
      violations.push(violation);

      // Check if this detector should trigger blocking
      if (blockList.includes(detectorName)) {
        shouldBlock = true;
      }
    }
  }

  return { shouldBlock, violations };
}

/**
 * Format violation message for user display
 */
export function formatViolationMessage(violations: Violation[], hookName: string = 'guardrails'): string {
  if (violations.length === 0) {
    return '';
  }

  const detectorNames = violations.map(v => v.detector).join(', ');
  return `[Enkrypt Guardrails - ${hookName}] Content blocked due to: ${detectorNames}`;
}

// ============================================================================
// TOOL UTILITIES
// ============================================================================

/**
 * Check if a tool is considered sensitive
 */
export function isSensitiveTool(toolName: string): boolean {
  const cfg = loadConfig();
  const patterns = cfg.sensitive_tools || [];

  for (const pattern of patterns) {
    if (pattern.includes('*')) {
      // Wildcard pattern
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      if (regex.test(toolName)) {
        return true;
      }
    } else {
      // Exact match or prefix match
      if (toolName === pattern || toolName.startsWith(pattern)) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// LOGGING
// ============================================================================

let logBuffer: LogEntry[] = [];
const LOG_FLUSH_INTERVAL = 5000; // 5 seconds
const LOG_BUFFER_SIZE = 100;

// Ensure log directory exists
function ensureLogDir(): void {
  try {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }
  } catch {
    // Ignore errors - logging is optional
  }
}

/**
 * Log an event
 */
export function logEvent(
  hook: string,
  event: string,
  data: Record<string, unknown> = {}
): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    hook,
    event,
    data,
  };

  logBuffer.push(entry);

  if (logBuffer.length >= LOG_BUFFER_SIZE) {
    flushLogs();
  }
}

/**
 * Log API response details
 */
function logApiResponse(
  hook: string,
  result: Record<string, unknown>,
  latency: number
): void {
  ensureLogDir();

  const entry = {
    timestamp: new Date().toISOString(),
    hook,
    latency_ms: latency,
    result_preview: JSON.stringify(result).slice(0, 500),
  };

  try {
    const logPath = path.join(LOG_DIR, 'enkrypt_api_response.jsonl');
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch {
    // Ignore logging errors
  }
}

/**
 * Log security alert
 */
export function logSecurityAlert(
  alertType: string,
  details: Record<string, unknown>,
  context: Record<string, unknown> = {}
): void {
  ensureLogDir();

  const entry = {
    timestamp: new Date().toISOString(),
    alert_type: alertType,
    details,
    context,
  };

  try {
    const logPath = path.join(LOG_DIR, 'security_alerts.jsonl');
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch {
    // Ignore logging errors
  }
}

/**
 * Flush log buffer to disk
 */
export function flushLogs(): void {
  if (logBuffer.length === 0) return;

  ensureLogDir();

  try {
    const logPath = path.join(LOG_DIR, 'combined_audit.jsonl');
    const content = logBuffer.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.appendFileSync(logPath, content);
    logBuffer = [];
  } catch {
    // Clear buffer even on error to prevent memory issues
    logBuffer = [];
  }
}

// Flush logs periodically
if (typeof setInterval !== 'undefined') {
  setInterval(flushLogs, LOG_FLUSH_INTERVAL);
}

// ============================================================================
// METRICS
// ============================================================================

const metrics: Map<string, HookMetrics> = new Map();

/**
 * Update metrics for a hook
 */
function updateMetrics(
  hookName: string,
  blocked: boolean,
  latencyMs: number,
  isError: boolean = false
): void {
  let hookMetrics = metrics.get(hookName);

  if (!hookMetrics) {
    hookMetrics = {
      totalCalls: 0,
      blocked: 0,
      allowed: 0,
      errors: 0,
      totalLatencyMs: 0,
    };
    metrics.set(hookName, hookMetrics);
  }

  hookMetrics.totalCalls++;
  hookMetrics.totalLatencyMs += latencyMs;

  if (isError) {
    hookMetrics.errors++;
  } else if (blocked) {
    hookMetrics.blocked++;
  } else {
    hookMetrics.allowed++;
  }
}

/**
 * Get metrics for all hooks
 */
export function getMetrics(): Record<string, HookMetrics & { avgLatencyMs: number }> {
  const result: Record<string, HookMetrics & { avgLatencyMs: number }> = {};

  metrics.forEach((m, hookName) => {
    result[hookName] = {
      ...m,
      avgLatencyMs: m.totalCalls > 0 ? m.totalLatencyMs / m.totalCalls : 0,
    };
  });

  return result;
}

/**
 * Reset metrics
 */
export function resetMetrics(): void {
  metrics.clear();
}

// ============================================================================
// EXCEPTIONS
// ============================================================================

/**
 * Error thrown when guardrails block a request
 */
export class GuardrailsViolationError extends Error {
  violations: Violation[];
  hookName: string;

  constructor(message: string, violations: Violation[], hookName: string) {
    super(message);
    this.name = 'GuardrailsViolationError';
    this.violations = violations;
    this.hookName = hookName;
  }
}
