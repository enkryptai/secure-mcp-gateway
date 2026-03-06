/**
 * Tests for Enkrypt AI Guardrails - Vercel AI SDK
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  parseEnkryptResponse,
  formatViolationMessage,
  isSensitiveTool,
  getDefaultConfig,
  loadConfig,
  DETECTOR_TYPES,
  type Violation,
} from '../src/enkrypt-guardrails';

describe('Enkrypt Guardrails Core', () => {
  describe('parseEnkryptResponse', () => {
    it('should return no violations for clean response', () => {
      // Actual Enkrypt API response format
      const response = {
        summary: {
          injection_attack: 0,
          pii: 0,
        },
        details: {},
      };

      const result = parseEnkryptResponse(response, ['injection_attack', 'pii']);

      expect(result.shouldBlock).toBe(false);
      expect(result.violations).toHaveLength(0);
    });

    it('should detect violations when detector returns 1 in summary', () => {
      const response = {
        summary: {
          injection_attack: 1,
          pii: 0,
        },
        details: {
          injection_attack: { safe: '0.01', attack: '0.99' },
        },
      };

      const result = parseEnkryptResponse(response, ['injection_attack']);

      expect(result.shouldBlock).toBe(true);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].detector).toBe('injection_attack');
    });

    it('should detect violations when toxicity is a list', () => {
      const response = {
        summary: {
          toxicity: ['toxicity', 'insult'],
        },
        details: {
          toxicity: { score: 0.8 },
        },
      };

      const result = parseEnkryptResponse(response, ['toxicity']);

      expect(result.shouldBlock).toBe(true);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].detector).toBe('toxicity');
    });

    it('should not block if violation not in block list', () => {
      const response = {
        summary: {
          injection_attack: 1,
        },
        details: {
          injection_attack: { safe: '0.01', attack: '0.99' },
        },
      };

      const result = parseEnkryptResponse(response, ['pii']); // injection not in block list

      expect(result.shouldBlock).toBe(false);
      expect(result.violations).toHaveLength(1); // Still detected, just not blocking
    });

    it('should handle empty response', () => {
      const result = parseEnkryptResponse({}, ['injection_attack']);

      expect(result.shouldBlock).toBe(false);
      expect(result.violations).toHaveLength(0);
    });

    it('should handle multiple violations', () => {
      const response = {
        summary: {
          injection_attack: 1,
          pii: 1,
          toxicity: 1,
        },
        details: {
          injection_attack: { attack: '0.9' },
          pii: {},
          toxicity: {},
        },
      };

      const result = parseEnkryptResponse(response, ['injection_attack', 'pii', 'toxicity']);

      expect(result.shouldBlock).toBe(true);
      expect(result.violations).toHaveLength(3);
    });
  });

  describe('formatViolationMessage', () => {
    it('should return empty string for no violations', () => {
      const message = formatViolationMessage([], 'test_hook');
      expect(message).toBe('');
    });

    it('should format single violation', () => {
      const violations: Violation[] = [
        { detector: 'injection_attack', score: 0.9, threshold: 0.5, detected: true },
      ];

      const message = formatViolationMessage(violations, 'transformParams');

      expect(message).toContain('Enkrypt Guardrails');
      expect(message).toContain('injection_attack');
      expect(message).toContain('transformParams');
    });

    it('should format multiple violations', () => {
      const violations: Violation[] = [
        { detector: 'injection_attack', score: 0.9, threshold: 0.5, detected: true },
        { detector: 'pii', score: 0.8, threshold: 0.5, detected: true },
      ];

      const message = formatViolationMessage(violations, 'test');

      expect(message).toContain('injection_attack');
      expect(message).toContain('pii');
    });
  });

  describe('isSensitiveTool', () => {
    it('should match exact tool names', () => {
      expect(isSensitiveTool('bash')).toBe(true);
      expect(isSensitiveTool('send_email')).toBe(true);
    });

    it('should match wildcard patterns', () => {
      expect(isSensitiveTool('shell_command')).toBe(true);
      expect(isSensitiveTool('delete_file')).toBe(true);
    });

    it('should return false for safe tools', () => {
      expect(isSensitiveTool('weather')).toBe(false);
      expect(isSensitiveTool('calculate')).toBe(false);
    });

    it('should handle prefix matches', () => {
      expect(isSensitiveTool('execute_sql_query')).toBe(true);
      expect(isSensitiveTool('run_command_async')).toBe(true);
    });
  });

  describe('getDefaultConfig', () => {
    it('should return valid configuration', () => {
      const config = getDefaultConfig();

      expect(config.enkrypt_api).toBeDefined();
      expect(config.enkrypt_api.url).toContain('enkryptai.com');
      expect(config.transformParams).toBeDefined();
      expect(config.transformParams.enabled).toBe(true);
      expect(config.wrapGenerate).toBeDefined();
      expect(config.sensitive_tools).toBeInstanceOf(Array);
    });

    it('should have all hooks configured', () => {
      const config = getDefaultConfig();

      expect(config.transformParams).toBeDefined();
      expect(config.wrapGenerate).toBeDefined();
      expect(config.wrapStream).toBeDefined();
      expect(config.prepareStep).toBeDefined();
      expect(config.onStepFinish).toBeDefined();
      expect(config.onToolCall).toBeDefined();
    });
  });

  describe('DETECTOR_TYPES', () => {
    it('should include all expected detectors', () => {
      expect(DETECTOR_TYPES).toContain('injection_attack');
      expect(DETECTOR_TYPES).toContain('pii');
      expect(DETECTOR_TYPES).toContain('toxicity');
      expect(DETECTOR_TYPES).toContain('nsfw');
      expect(DETECTOR_TYPES).toContain('bias');
    });
  });
});
