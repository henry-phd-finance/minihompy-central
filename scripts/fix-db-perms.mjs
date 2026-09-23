import pg from 'pg';
const { Client } = pg;

async function fixAndDebugDb() {
  const client = new Client({
    connectionString: 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'
  });

  try {
    await client.connect();
    console.log('✅ Connected to local Postgres as superuser.');
    
    // Fix permissions for service_role
    await client.query(`
      GRANT USAGE ON SCHEMA private TO service_role;
      GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA private TO service_role;
      GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA private TO service_role;
      NOTIFY pgrst, 'reload schema';
    `);
    console.log('✅ Granted necessary permissions to service_role and reloaded schema.');

    // Fetch data directly via superuser to bypass any PostgREST cache issues temporarily
    const res = await client.query('SELECT id, handle, status FROM private.identity_members;');
    console.log('\n--- identity_members ---');
    console.table(res.rows);

    const res2 = await client.query('SELECT id, member_id, origin, status FROM private.identity_sites;');
    console.log('\n--- identity_sites ---');
    console.table(res2.rows);

  } catch (err) {
    console.error('❌ Error:', err.message);
  } finally {
    await client.end();
  }
}

fixAndDebugDb();
