/**
 * Minihompy Central Identity - Complete Verification Runner
 * Runs all test suites from Step C1 to Step C8 sequentially.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const suites = [
  { name: 'Runtime source consistency', file: 'verify-runtime-source.mjs' },
  { name: 'Deployment prerequisites', file: 'verify-deployment.mjs' },
  { name: 'Protocol & Token Security', file: 'verify-shared-identity-protocol.mjs' },
  { name: 'Member navigation (SQL)', file: 'verify-member-navigation.mjs' },
  { name: 'Step C2: Directory & CORS', file: 'verify-identity-directory.mjs' },
  { name: 'Verified registration, Auth proof & single-use login (SQL)', file: 'verify-identity-security.mjs' },
  { name: 'Member writing proof, grants and logout (SQL)', file: 'verify-member-writing.mjs' },
  { name: 'Writing logout UI failure recovery', file: 'verify-writing-logout-ui.mjs' },
  { name: 'Existing identity migration', file: 'verify-identity-upgrade.mjs' },
  { name: 'Step C5: Visits Issue', file: 'verify-identity-visit-issue.mjs' },
  { name: 'Step C6: Visits Resolve', file: 'verify-identity-visit-resolve.mjs' },
  { name: 'Step C7: Identity Page (/visit)', file: 'verify-identity-page-visit.mjs' },
  { name: 'Step C8: UI Pages (/login, /complete, /logout)', file: 'verify-identity-page-ui.mjs' },
];

console.log('=============================================================');
console.log('🚀 RUNNING ALL MINIHOMPY CENTRAL VERIFICATION TEST SUITES');
console.log('=============================================================\n');

let passed = 0;
let failed = 0;

for (const suite of suites) {
  const filePath = resolve(__dirname, suite.file);
  console.log(`▶ Running ${suite.name} (${suite.file})...`);
  const result = spawnSync(process.execPath, [filePath], {
    stdio: 'inherit',
    encoding: 'utf-8',
  });

  if (result.status === 0) {
    passed++;
  } else {
    failed++;
    console.error(`\n❌ Failed: ${suite.name}`);
    process.exit(1);
  }
}

console.log('=============================================================');
console.log(`🎉 ALL ${passed} TEST SUITES PASSED PERFECTLY (100% SUCCESS)`);
console.log('=============================================================\n');
