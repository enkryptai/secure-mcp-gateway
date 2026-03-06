/**
 * Tool Protection Example - Enkrypt AI Guardrails for Vercel AI SDK
 *
 * This example demonstrates how to protect tool calls with guardrails.
 *
 * Usage:
 *   export OPENAI_API_KEY="your-openai-key"
 *   export ENKRYPT_API_KEY="your-enkrypt-key"
 *   npx ts-node examples/tool-protection.ts
 */

import { generateText, tool, wrapLanguageModel } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';
import {
  createEnkryptMiddleware,
  wrapToolWithGuardrails,
  isSensitiveTool,
  GuardrailsViolationError,
  getMetrics,
} from '../src';

// Define tools
const weatherTool = tool({
  description: 'Get the current weather for a city',
  parameters: z.object({
    city: z.string().describe('The city name'),
  }),
  execute: async ({ city }) => {
    // Simulated weather data
    const temps: Record<string, number> = {
      'new york': 72,
      'london': 58,
      'tokyo': 65,
      'paris': 68,
    };
    const temp = temps[city.toLowerCase()] || 70;
    return { city, temperature: temp, unit: 'F', conditions: 'Partly cloudy' };
  },
});

const executeCommandTool = tool({
  description: 'Execute a system command',
  parameters: z.object({
    command: z.string().describe('The command to execute'),
  }),
  execute: async ({ command }) => {
    // This is a sensitive tool - should be monitored
    return { output: `Simulated output for: ${command}`, exitCode: 0 };
  },
});

const sendEmailTool = tool({
  description: 'Send an email',
  parameters: z.object({
    to: z.string().describe('Recipient email'),
    subject: z.string().describe('Email subject'),
    body: z.string().describe('Email body'),
  }),
  execute: async ({ to, subject, body }) => {
    // Simulated email sending
    return { sent: true, messageId: `msg-${Date.now()}` };
  },
});

async function main() {
  console.log('='.repeat(60));
  console.log('Enkrypt AI Guardrails - Tool Protection Example');
  console.log('='.repeat(60));

  // Check sensitive tool detection
  console.log('\nSensitive Tool Detection:');
  const toolNames = ['weather', 'execute_command', 'run_command', 'send_email', 'bash'];
  toolNames.forEach(name => {
    console.log(`  ${name}: ${isSensitiveTool(name) ? 'SENSITIVE' : 'safe'}`);
  });

  console.log('\n' + '-'.repeat(60));

  // Wrap sensitive tools with guardrails
  const protectedExecuteCommand = wrapToolWithGuardrails(executeCommandTool, {
    checkInputs: true,
    checkOutputs: true,
    blockOnViolation: true,
    onViolation: (violations, phase) => {
      console.log(`[Tool violation - ${phase}]:`, violations.map(v => v.detector).join(', '));
    },
  });

  const protectedSendEmail = wrapToolWithGuardrails(sendEmailTool, {
    checkInputs: true,
    checkOutputs: true,
    blockOnViolation: true,
  });

  // Create protected model
  const protectedModel = wrapLanguageModel({
    model: openai('gpt-4o-mini'),
    middleware: createEnkryptMiddleware({
      blockOnViolation: true,
      onViolation: (violations, hookName) => {
        console.log(`[Middleware violation - ${hookName}]:`, violations.map(v => v.detector).join(', '));
      },
    }),
  });

  // Test 1: Safe tool call
  console.log('\n[Test 1] Safe tool call (weather):');
  console.log('Prompt: "What is the weather in Paris?"');

  try {
    const result1 = await generateText({
      model: protectedModel,
      tools: { weather: weatherTool },
      maxSteps: 2,
      prompt: 'What is the weather in Paris?',
    });
    console.log(`Response: ${result1.text.slice(0, 300)}`);
    if (result1.toolCalls?.length) {
      console.log('Tool calls:', result1.toolCalls.map(t => t.toolName).join(', '));
    }
  } catch (error) {
    console.log(`Error: ${error}`);
  }

  console.log('\n' + '-'.repeat(60));

  // Test 2: Protected sensitive tool
  console.log('\n[Test 2] Protected sensitive tool (execute_command):');
  console.log('Prompt: "Run the ls command"');

  try {
    const result2 = await generateText({
      model: protectedModel,
      tools: { execute_command: protectedExecuteCommand },
      maxSteps: 2,
      prompt: 'Run the ls command to list files',
    });
    console.log(`Response: ${result2.text.slice(0, 300)}`);
  } catch (error) {
    if (error instanceof GuardrailsViolationError) {
      console.log(`BLOCKED: ${error.message}`);
    } else {
      console.log(`Error: ${error}`);
    }
  }

  console.log('\n' + '-'.repeat(60));

  // Test 3: Tool with PII attempt
  console.log('\n[Test 3] Tool with PII (send_email):');
  console.log('Prompt: "Send an email with my SSN 123-45-6789"');

  try {
    const result3 = await generateText({
      model: protectedModel,
      tools: { send_email: protectedSendEmail },
      maxSteps: 2,
      prompt: 'Send an email to test@example.com with my SSN 123-45-6789 in the body',
    });
    console.log(`Response: ${result3.text.slice(0, 300)}`);
  } catch (error) {
    if (error instanceof GuardrailsViolationError) {
      console.log(`BLOCKED: ${error.message}`);
    } else {
      console.log(`Error: ${error}`);
    }
  }

  console.log('\n' + '-'.repeat(60));

  // Show metrics
  console.log('\nGuardrails Metrics:');
  const metrics = getMetrics();
  Object.entries(metrics).forEach(([hook, m]) => {
    if (m.totalCalls > 0) {
      console.log(`  ${hook}: ${m.totalCalls} calls, ${m.blocked} blocked, ${m.avgLatencyMs.toFixed(0)}ms avg`);
    }
  });

  console.log('\n' + '='.repeat(60));
  console.log('Tool protection demo completed.');
}

main().catch(console.error);
