/**
 * Enkrypt AI Guardrails Examples Index
 *
 * Run any example with:
 *   npx ts-node examples/<example-name>.ts
 *
 * Examples:
 *   - basic-usage.ts         - Basic text generation with guardrails
 *   - streaming-example.ts   - Streaming with guardrails protection
 *   - tool-protection.ts     - Tool call monitoring and protection
 *   - demo-injection-attack.ts - Test injection attack detection
 *   - demo-pii-detection.ts    - Test PII detection
 */

export const examples = [
  'basic-usage',
  'streaming-example',
  'tool-protection',
  'demo-injection-attack',
  'demo-pii-detection',
] as const;

console.log('Enkrypt AI Guardrails - Vercel AI SDK Examples');
console.log('='.repeat(50));
console.log('\nAvailable examples:');
examples.forEach((name, i) => {
  console.log(`  ${i + 1}. npx ts-node examples/${name}.ts`);
});
console.log('\nMake sure to set environment variables:');
console.log('  export OPENAI_API_KEY="your-openai-key"');
console.log('  export ENKRYPT_API_KEY="your-enkrypt-key"');
