import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(__dirname, '../.env.local');

async function debugDb() {
  if (!fs.existsSync(envPath)) {
    console.error('❌ .env.local file not found!');
    return;
  }

  const envContent = fs.readFileSync(envPath, 'utf8');
  const match = envContent.match(/CENTRAL_SERVICE_ROLE_KEY\s*=\s*["']?([^"'\n]+)["']?/);
  
  if (!match || !match[1]) {
    console.error('❌ CENTRAL_SERVICE_ROLE_KEY not found in .env.local');
    return;
  }

  const serviceRoleKey = match[1];
  console.log('✅ Found Service Role Key:', serviceRoleKey.substring(0, 15) + '...');

  const dbUrl = 'http://127.0.0.1:54321/rest/v1';

  try {
    const res = await fetch(`${dbUrl}/identity_members?select=*`, {
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Accept-Profile': 'private'
      }
    });

    if (!res.ok) {
      console.error('❌ DB Query Failed:', res.status, await res.text());
      return;
    }

    const members = await res.json();
    console.log('\n--- identity_members ---');
    console.table(members);

    const res2 = await fetch(`${dbUrl}/identity_sites?select=*`, {
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Accept-Profile': 'private'
      }
    });
    
    if (res2.ok) {
      const sites = await res2.json();
      console.log('\n--- identity_sites ---');
      console.table(sites);
    }
    
  } catch (err) {
    console.error('❌ Fetch error:', err.message);
  }
}

debugDb();
