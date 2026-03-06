/**
 * Enkrypt AI Guardrails Middleware for Vercel AI SDK
 *
 * This module provides language model middleware that integrates
 * Enkrypt AI Guardrails with Vercel AI SDK's generateText and streamText.
 *
 * Features:
 * - Pre-request input validation (transformParams)
 * - Post-generation output scanning (wrapGenerate, wrapStream)
 * - Tool input/output protection
 * - Configurable blocking vs. audit-only modes
 *
 * Usage:
 *   import { wrapLanguageModel } from 'ai';
 *   import { createEnkryptMiddleware } from '@enkrypt-ai/vercel-ai-sdk';
 *
 *   const protectedModel = wrapLanguageModel({
 *     model: openai('gpt-4'),
 *     middleware: createEnkryptMiddleware(),
 *   });
 */

import {
  checkWithEnkryptApi,
  formatViolationMessage,
  isHookEnabled,
  isSensitiveTool,
  loadConfig,
  logEvent,
  logSecurityAlert,
  GuardrailsViolationError,
  type CheckResult,
  type Violation,
} from './enkrypt-guardrails';

// ============================================================================
// TYPES - Vercel AI SDK Compatible
// ============================================================================

/**
 * Language Model V3 Call Options (simplified for our use)
 */
export interface LanguageModelCallOptions {
  prompt?: string;
  messages?: Array<{
    role: 'user' | 'assistant' | 'system' | 'tool';
    content: string | Array<{ type: string; text?: string }>;
  }>;
  system?: string;
  tools?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Generation result
 */
export interface GenerateResult {
  text: string;
  toolCalls?: Array<{
    toolCallId: string;
    toolName: string;
    args: Record<string, unknown>;
  }>;
  finishReason?: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  [key: string]: unknown;
}

/**
 * Stream result
 */
export interface StreamResult {
  stream: ReadableStream;
  [key: string]: unknown;
}

/**
 * Middleware configuration options
 */
export interface EnkryptMiddlewareOptions {
  /**
   * Block requests that violate policies (default: true)
   */
  blockOnViolation?: boolean;

  /**
   * Only log violations, never block (default: false)
   */
  logOnlyMode?: boolean;

  /**
   * Check inputs before model calls (default: true)
   */
  checkInputs?: boolean;

  /**
   * Check outputs after model calls (default: true)
   */
  checkOutputs?: boolean;

  /**
   * Custom error message prefix
   */
  errorMessagePrefix?: string;

  /**
   * Callback when a violation is detected
   */
  onViolation?: (violations: Violation[], hookName: string) => void;
}

/**
 * Language Model V3 Middleware interface (Vercel AI SDK compatible)
 */
export interface LanguageModelV3Middleware {
  /**
   * Transform parameters before model call
   */
  transformParams?: (options: {
    type: 'generate' | 'stream';
    params: LanguageModelCallOptions;
  }) => Promise<LanguageModelCallOptions>;

  /**
   * Wrap non-streaming generation
   */
  wrapGenerate?: (options: {
    doGenerate: () => Promise<GenerateResult>;
    params: LanguageModelCallOptions;
    model: unknown;
  }) => Promise<GenerateResult>;

  /**
   * Wrap streaming generation
   */
  wrapStream?: (options: {
    doStream: () => Promise<StreamResult>;
    params: LanguageModelCallOptions;
    model: unknown;
  }) => Promise<StreamResult>;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Extract text from messages array
 */
function extractMessagesText(messages: LanguageModelCallOptions['messages']): string {
  if (!messages || !Array.isArray(messages)) return '';

  const textParts: string[] = [];

  for (const msg of messages) {
    if (typeof msg.content === 'string') {
      textParts.push(msg.content);
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (part.type === 'text' && part.text) {
          textParts.push(part.text);
        }
      }
    }
  }

  return textParts.join('\n');
}

/**
 * Extract combined input text from params
 */
function extractInputText(params: LanguageModelCallOptions): string {
  const parts: string[] = [];

  if (params.prompt) {
    parts.push(params.prompt);
  }

  if (params.system) {
    parts.push(params.system);
  }

  if (params.messages) {
    parts.push(extractMessagesText(params.messages));
  }

  return parts.join('\n');
}

/**
 * Create blocked response message
 */
function createBlockedMessage(violations: Violation[], hookName: string): string {
  const detectors = violations.map(v => v.detector).join(', ');
  return (
    `I cannot process this request due to security policy violations.\n\n` +
    `Detected issues: ${detectors}\n\n` +
    `Please rephrase your request without the flagged content.`
  );
}

// ============================================================================
// MIDDLEWARE FACTORY
// ============================================================================

/**
 * Create Enkrypt AI Guardrails middleware for Vercel AI SDK
 *
 * @example
 * ```typescript
 * import { wrapLanguageModel, generateText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 * import { createEnkryptMiddleware } from '@enkrypt-ai/vercel-ai-sdk';
 *
 * const protectedModel = wrapLanguageModel({
 *   model: openai('gpt-4'),
 *   middleware: createEnkryptMiddleware({
 *     blockOnViolation: true,
 *   }),
 * });
 *
 * const { text } = await generateText({
 *   model: protectedModel,
 *   prompt: 'Hello, world!',
 * });
 * ```
 */
export function createEnkryptMiddleware(
  options: EnkryptMiddlewareOptions = {}
): LanguageModelV3Middleware {
  const {
    blockOnViolation = true,
    logOnlyMode = false,
    checkInputs = true,
    checkOutputs = true,
    errorMessagePrefix = '[Enkrypt Guardrails]',
    onViolation,
  } = options;

  // Ensure config is loaded
  loadConfig();

  return {
    /**
     * Transform params - runs BEFORE model call
     * Use for input validation
     */
    transformParams: async ({ type, params }) => {
      if (!checkInputs || !isHookEnabled('transformParams')) {
        return params;
      }

      const inputText = extractInputText(params);
      if (!inputText.trim()) {
        return params;
      }

      logEvent('transformParams', 'check_start', {
        type,
        inputLength: inputText.length,
      });

      const result = await checkWithEnkryptApi(inputText, 'transformParams');

      if (result.violations.length > 0) {
        logSecurityAlert('input_violation', {
          hook: 'transformParams',
          type,
          violations: result.violations,
          inputPreview: inputText.slice(0, 200),
        });

        onViolation?.(result.violations, 'transformParams');

        if (result.shouldBlock && blockOnViolation && !logOnlyMode) {
          throw new GuardrailsViolationError(
            formatViolationMessage(result.violations, 'transformParams'),
            result.violations,
            'transformParams'
          );
        }
      }

      logEvent('transformParams', 'check_complete', {
        type,
        violationsCount: result.violations.length,
        blocked: result.shouldBlock && blockOnViolation && !logOnlyMode,
      });

      return params;
    },

    /**
     * Wrap generate - wraps non-streaming generation
     * Use for output validation
     */
    wrapGenerate: async ({ doGenerate, params, model }) => {
      logEvent('wrapGenerate', 'call_start', {
        hasTools: !!params.tools,
      });

      // Execute the generation
      const result = await doGenerate();

      // Check output if enabled
      if (checkOutputs && isHookEnabled('wrapGenerate') && result.text) {
        const checkResult = await checkWithEnkryptApi(result.text, 'wrapGenerate');

        if (checkResult.violations.length > 0) {
          logSecurityAlert('output_violation', {
            hook: 'wrapGenerate',
            violations: checkResult.violations,
            outputPreview: result.text.slice(0, 200),
          });

          onViolation?.(checkResult.violations, 'wrapGenerate');

          if (checkResult.shouldBlock && blockOnViolation && !logOnlyMode) {
            // Return a modified result with blocked message
            return {
              ...result,
              text: createBlockedMessage(checkResult.violations, 'wrapGenerate'),
              _guardrailsBlocked: true,
              _guardrailsViolations: checkResult.violations,
            };
          }
        }

        logEvent('wrapGenerate', 'output_checked', {
          violationsCount: checkResult.violations.length,
        });
      }

      // Check tool calls if present
      if (result.toolCalls && result.toolCalls.length > 0) {
        for (const toolCall of result.toolCalls) {
          if (isSensitiveTool(toolCall.toolName)) {
            logSecurityAlert('sensitive_tool_call', {
              hook: 'wrapGenerate',
              toolName: toolCall.toolName,
              toolCallId: toolCall.toolCallId,
            });

            // Check tool arguments
            if (isHookEnabled('onToolCall')) {
              const argsText = JSON.stringify(toolCall.args);
              const toolCheckResult = await checkWithEnkryptApi(argsText, 'onToolCall');

              if (toolCheckResult.violations.length > 0) {
                logSecurityAlert('tool_args_violation', {
                  hook: 'onToolCall',
                  toolName: toolCall.toolName,
                  violations: toolCheckResult.violations,
                });

                onViolation?.(toolCheckResult.violations, 'onToolCall');
              }
            }
          }
        }
      }

      logEvent('wrapGenerate', 'call_complete', {
        hasText: !!result.text,
        toolCallsCount: result.toolCalls?.length || 0,
      });

      return result;
    },

    /**
     * Wrap stream - wraps streaming generation
     * Note: For streaming, we primarily check inputs (via transformParams)
     * and log outputs, but blocking mid-stream is complex
     */
    wrapStream: async ({ doStream, params, model }) => {
      logEvent('wrapStream', 'stream_start', {
        hasTools: !!params.tools,
      });

      // Execute the stream
      const result = await doStream();

      // For streaming, we can wrap the stream to monitor chunks
      // but blocking mid-stream requires buffering which adds latency
      // Instead, we rely on transformParams for input checking

      if (checkOutputs && isHookEnabled('wrapStream')) {
        // Create a transform stream that monitors output
        const originalStream = result.stream;
        let fullText = '';

        const transformStream = new TransformStream({
          transform(chunk, controller) {
            // Pass through the chunk
            controller.enqueue(chunk);

            // Accumulate text for post-stream checking
            if (typeof chunk === 'string') {
              fullText += chunk;
            } else if (chunk?.type === 'text-delta' && chunk.textDelta) {
              fullText += chunk.textDelta;
            }
          },
          async flush(controller) {
            // Check accumulated text after stream completes
            if (fullText.trim()) {
              const checkResult = await checkWithEnkryptApi(fullText, 'wrapStream');

              if (checkResult.violations.length > 0) {
                logSecurityAlert('stream_output_violation', {
                  hook: 'wrapStream',
                  violations: checkResult.violations,
                  outputLength: fullText.length,
                });

                onViolation?.(checkResult.violations, 'wrapStream');

                // Note: We can't block after streaming, only log
                logEvent('wrapStream', 'post_stream_violation', {
                  violationsCount: checkResult.violations.length,
                  blocked: false, // Can't block after stream
                });
              }
            }
          },
        });

        return {
          ...result,
          stream: originalStream.pipeThrough(transformStream),
        };
      }

      logEvent('wrapStream', 'stream_passthrough', {});

      return result;
    },
  };
}

// ============================================================================
// CONVENIENCE FACTORIES
// ============================================================================

/**
 * Create a blocking middleware that always blocks on violations
 */
export function createBlockingMiddleware(
  options: Omit<EnkryptMiddlewareOptions, 'blockOnViolation' | 'logOnlyMode'> = {}
): LanguageModelV3Middleware {
  return createEnkryptMiddleware({
    ...options,
    blockOnViolation: true,
    logOnlyMode: false,
  });
}

/**
 * Create an audit-only middleware that logs but never blocks
 */
export function createAuditMiddleware(
  options: Omit<EnkryptMiddlewareOptions, 'blockOnViolation' | 'logOnlyMode'> = {}
): LanguageModelV3Middleware {
  return createEnkryptMiddleware({
    ...options,
    blockOnViolation: false,
    logOnlyMode: true,
  });
}

/**
 * Create middleware that only checks inputs (pre-model)
 */
export function createInputOnlyMiddleware(
  options: Omit<EnkryptMiddlewareOptions, 'checkInputs' | 'checkOutputs'> = {}
): LanguageModelV3Middleware {
  return createEnkryptMiddleware({
    ...options,
    checkInputs: true,
    checkOutputs: false,
  });
}

/**
 * Create middleware that only checks outputs (post-model)
 */
export function createOutputOnlyMiddleware(
  options: Omit<EnkryptMiddlewareOptions, 'checkInputs' | 'checkOutputs'> = {}
): LanguageModelV3Middleware {
  return createEnkryptMiddleware({
    ...options,
    checkInputs: false,
    checkOutputs: true,
  });
}

// ============================================================================
// TOOL PROTECTION UTILITIES
// ============================================================================

/**
 * Create a protected tool wrapper that checks inputs/outputs
 *
 * @example
 * ```typescript
 * import { tool } from 'ai';
 * import { wrapToolWithGuardrails } from '@enkrypt-ai/vercel-ai-sdk';
 *
 * const weatherTool = tool({
 *   description: 'Get weather for a city',
 *   parameters: z.object({ city: z.string() }),
 *   execute: async ({ city }) => {
 *     return { temperature: 72 };
 *   },
 * });
 *
 * const protectedWeatherTool = wrapToolWithGuardrails(weatherTool, {
 *   checkInputs: true,
 *   checkOutputs: true,
 * });
 * ```
 */
export function wrapToolWithGuardrails<T extends { execute?: (...args: unknown[]) => unknown }>(
  tool: T,
  options: {
    checkInputs?: boolean;
    checkOutputs?: boolean;
    blockOnViolation?: boolean;
    onViolation?: (violations: Violation[], phase: 'input' | 'output') => void;
  } = {}
): T {
  const {
    checkInputs = true,
    checkOutputs = true,
    blockOnViolation = true,
    onViolation,
  } = options;

  if (!tool.execute) {
    return tool;
  }

  const originalExecute = tool.execute;

  const wrappedExecute = async (...args: unknown[]) => {
    // Check inputs
    if (checkInputs && isHookEnabled('onToolCall')) {
      const inputText = JSON.stringify(args);
      const inputResult = await checkWithEnkryptApi(inputText, 'onToolCall');

      if (inputResult.violations.length > 0) {
        logSecurityAlert('tool_input_violation', {
          violations: inputResult.violations,
        });

        onViolation?.(inputResult.violations, 'input');

        if (inputResult.shouldBlock && blockOnViolation) {
          throw new GuardrailsViolationError(
            'Tool input blocked by guardrails',
            inputResult.violations,
            'onToolCall'
          );
        }
      }
    }

    // Execute original tool
    const result = await (originalExecute as (...args: unknown[]) => Promise<unknown>)(...args);

    // Check outputs
    if (checkOutputs && isHookEnabled('onToolCall')) {
      const outputText = JSON.stringify(result);
      const outputResult = await checkWithEnkryptApi(outputText, 'onToolCall');

      if (outputResult.violations.length > 0) {
        logSecurityAlert('tool_output_violation', {
          violations: outputResult.violations,
        });

        onViolation?.(outputResult.violations, 'output');

        // Don't block on output, just log
      }
    }

    return result;
  };

  return {
    ...tool,
    execute: wrappedExecute,
  } as T;
}

// ============================================================================
// STEP CALLBACKS
// ============================================================================

/**
 * Create prepareStep callback with guardrails
 *
 * @example
 * ```typescript
 * import { streamText } from 'ai';
 * import { createPrepareStepWithGuardrails } from '@enkrypt-ai/vercel-ai-sdk';
 *
 * const result = await streamText({
 *   model: protectedModel,
 *   prompt: 'Hello',
 *   prepareStep: createPrepareStepWithGuardrails({
 *     blockOnViolation: true,
 *   }),
 * });
 * ```
 */
export function createPrepareStepWithGuardrails(options: {
  blockOnViolation?: boolean;
  onViolation?: (violations: Violation[]) => void;
} = {}) {
  const { blockOnViolation = true, onViolation } = options;

  return async (context: {
    step: number;
    messages: Array<{ role: string; content: string }>;
    tools?: Record<string, unknown>;
  }) => {
    if (!isHookEnabled('prepareStep')) {
      return context;
    }

    // Check the last user message
    const lastUserMessage = [...context.messages]
      .reverse()
      .find(m => m.role === 'user');

    if (lastUserMessage?.content) {
      const result = await checkWithEnkryptApi(lastUserMessage.content, 'prepareStep');

      if (result.violations.length > 0) {
        logSecurityAlert('prepareStep_violation', {
          step: context.step,
          violations: result.violations,
        });

        onViolation?.(result.violations);

        if (result.shouldBlock && blockOnViolation) {
          throw new GuardrailsViolationError(
            'Step blocked by guardrails',
            result.violations,
            'prepareStep'
          );
        }
      }
    }

    logEvent('prepareStep', 'step_prepared', {
      step: context.step,
      messagesCount: context.messages.length,
    });

    return context;
  };
}

/**
 * Create onStepFinish callback with guardrails
 */
export function createOnStepFinishWithGuardrails(options: {
  onViolation?: (violations: Violation[], stepInfo: Record<string, unknown>) => void;
} = {}) {
  const { onViolation } = options;

  return async (context: {
    step: number;
    text?: string;
    toolCalls?: Array<{ toolName: string; args: unknown }>;
    toolResults?: unknown[];
    finishReason?: string;
    usage?: { promptTokens: number; completionTokens: number };
  }) => {
    if (!isHookEnabled('onStepFinish')) {
      return;
    }

    // Check the generated text
    if (context.text) {
      const result = await checkWithEnkryptApi(context.text, 'onStepFinish');

      if (result.violations.length > 0) {
        logSecurityAlert('onStepFinish_violation', {
          step: context.step,
          violations: result.violations,
          textPreview: context.text.slice(0, 200),
        });

        onViolation?.(result.violations, {
          step: context.step,
          finishReason: context.finishReason,
        });
      }
    }

    // Check tool results
    if (context.toolResults) {
      for (const toolResult of context.toolResults) {
        const resultText = JSON.stringify(toolResult);
        const result = await checkWithEnkryptApi(resultText, 'onStepFinish');

        if (result.violations.length > 0) {
          logSecurityAlert('tool_result_violation', {
            step: context.step,
            violations: result.violations,
          });
        }
      }
    }

    logEvent('onStepFinish', 'step_finished', {
      step: context.step,
      hasText: !!context.text,
      toolCallsCount: context.toolCalls?.length || 0,
      finishReason: context.finishReason,
      usage: context.usage,
    });
  };
}
