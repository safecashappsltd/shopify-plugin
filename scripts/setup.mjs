import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const envExamplePath = path.join(rootDir, '.env.example');
const envPath = path.join(rootDir, '.env');
const dataDir = path.join(rootDir, 'data');

console.log('\n============================================================');
console.log('  KashCash for Shopify - Automated Setup & Health Wizard');
console.log('============================================================\n');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('[OK] Created ./data directory for SQLite storage.');
} else {
  console.log('[OK] ./data directory already exists.');
}

if (!fs.existsSync(envPath)) {
  const template = fs.readFileSync(envExamplePath, 'utf8');
  const freshEncryptionKey = crypto.randomBytes(32).toString('hex');
  const populated = template.replace(
    /ENCRYPTION_KEY=[0-9a-fA-F]{64}/,
    `ENCRYPTION_KEY=${freshEncryptionKey}`
  );
  fs.writeFileSync(envPath, populated, 'utf8');
  console.log('[OK] Generated .env with a fresh 256-bit AES-GCM ENCRYPTION_KEY.');
} else {
  console.log('[OK] .env file already exists (kept existing settings).');
}

console.log('\nNext steps:');
console.log('  1. Edit .env and set SHOPIFY_API_KEY, SHOPIFY_API_SECRET, and APP_BASE_URL');
console.log('  2. Start locally:      npm run dev');
console.log('  3. Or via Docker:      docker compose up -d --build');
console.log('  4. Open Onboarding:    http://localhost:3000/app\n');
