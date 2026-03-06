/**
 * Tests for Enkrypt AI Guardrails Middleware - Vercel AI SDK
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createEnkryptMiddleware,
  createBlockingMiddleware,
  createAuditMiddleware,
  createInputOnlyMiddleware,
  createOutputOnlyMiddleware,
} from '../src/enkrypt-middleware';

// Mock the core module
vi.mock('../src/enkrypt-guardrails', async () => {
  const actual = await vi.importActual('../src/enkrypt-guardrails');
  return {
    ...actual,
    checkWithEnkryptApi: vi.fn().mockResolvedValue({
      shouldBlock: false,
      violations: [],
      rawResult: null,
    }),
    loadConfig: vi.fn().mockReturnValue({
      enkrypt_api: { api_key: 'test-key' },
      transformParams: { enabled: true, block: ['injection_attack'] },
      wrapGenerate: { enabled: true, block: ['pii'] },
      wrapStream: { enabled: true, block: ['toxicity'] },
      prepareStep: { enabled: true, block: [] },
      onStepFinish: { enabled: true, block: [] },
      onToolCall: { enabled: true, block: ['injection_attack'] },
      sensitive_tools: ['bash', 'delete_*'],
    }),
    isHookEnabled: vi.fn().mockReturnValue(true),
    logEvent: vi.fn(),
    logSecurityAlert: vi.fn(),
  };
});

describe('Enkrypt Middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createEnkryptMiddleware', () => {
    it('should create middleware with default options', () => {
      const middleware = createEnkryptMiddleware();

      expect(middleware).toBeDefined();
      expect(middleware.transformParams).toBeDefined();
      expect(middleware.wrapGenerate).toBeDefined();
      expect(middleware.wrapStream).toBeDefined();
    });

    it('should create middleware with custom options', () => {
      const onViolation = vi.fn();
      const middleware = createEnkryptMiddleware({
        blockOnViolation: false,
        logOnlyMode: true,
        onViolation,
      });

      expect(middleware).toBeDefined();
    });
  });

  describe('transformParams', () => {
    it('should pass through params when no violations', async () => {
      const middleware = createEnkryptMiddleware();
      const params = {
        prompt: 'Hello world',
        messages: [],
      };

      const result = await middleware.transformParams!({
        type: 'generate',
        params,
      });

      expect(result).toBe(params);
    });

    it('should pass through empty prompts', async () => {
      const middleware = createEnkryptMiddleware();
      const params = {
        prompt: '',
        messages: [],
      };

      const result = await middleware.transformParams!({
        type: 'generate',
        params,
      });

      expect(result).toBe(params);
    });
  });

  describe('wrapGenerate', () => {
    it('should call doGenerate and return result', async () => {
      const middleware = createEnkryptMiddleware();
      const mockResult = { text: 'Hello!', toolCalls: [] };
      const doGenerate = vi.fn().mockResolvedValue(mockResult);

      const result = await middleware.wrapGenerate!({
        doGenerate,
        params: { prompt: 'Test' },
        model: {},
      });

      expect(doGenerate).toHaveBeenCalled();
      expect(result.text).toBe('Hello!');
    });
  });

  describe('wrapStream', () => {
    it('should call doStream and return result', async () => {
      const middleware = createEnkryptMiddleware();
      const mockStream = new ReadableStream();
      const doStream = vi.fn().mockResolvedValue({ stream: mockStream });

      const result = await middleware.wrapStream!({
        doStream,
        params: { prompt: 'Test' },
        model: {},
      });

      expect(doStream).toHaveBeenCalled();
      expect(result.stream).toBeDefined();
    });
  });

  describe('createBlockingMiddleware', () => {
    it('should create middleware that blocks on violations', () => {
      const middleware = createBlockingMiddleware();

      expect(middleware).toBeDefined();
      expect(middleware.transformParams).toBeDefined();
    });
  });

  describe('createAuditMiddleware', () => {
    it('should create middleware that only audits', () => {
      const middleware = createAuditMiddleware();

      expect(middleware).toBeDefined();
    });
  });

  describe('createInputOnlyMiddleware', () => {
    it('should create middleware that only checks inputs', () => {
      const middleware = createInputOnlyMiddleware();

      expect(middleware).toBeDefined();
      expect(middleware.transformParams).toBeDefined();
    });
  });

  describe('createOutputOnlyMiddleware', () => {
    it('should create middleware that only checks outputs', () => {
      const middleware = createOutputOnlyMiddleware();

      expect(middleware).toBeDefined();
      expect(middleware.wrapGenerate).toBeDefined();
    });
  });
});

describe('Helper Functions', () => {
  describe('extractMessagesText', () => {
    // This is internal, but we can test via transformParams
    it('should handle string content', async () => {
      const middleware = createEnkryptMiddleware();
      const params = {
        messages: [
          { role: 'user' as const, content: 'Hello' },
          { role: 'assistant' as const, content: 'Hi there' },
        ],
      };

      const result = await middleware.transformParams!({
        type: 'generate',
        params,
      });

      // Should not throw and return params
      expect(result).toBe(params);
    });

    it('should handle array content (multimodal)', async () => {
      const middleware = createEnkryptMiddleware();
      const params = {
        messages: [
          {
            role: 'user' as const,
            content: [
              { type: 'text', text: 'What is this?' },
              { type: 'image', imageUrl: 'data:...' },
            ],
          },
        ],
      };

      const result = await middleware.transformParams!({
        type: 'generate',
        params,
      });

      expect(result).toBe(params);
    });
  });
});
