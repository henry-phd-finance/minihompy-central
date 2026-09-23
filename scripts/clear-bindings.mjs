import pkg from 'pg';
const { Client } = pkg;

async function clearBindings() {
  const client = new Client({
    connectionString: "postgresql://postgres:postgres@localhost:54322/postgres"
  });

  try {
    await client.connect();
    const result = await client.query("DELETE FROM private.identity_bindings");
    console.log(`Deleted ${result.rowCount} bindings.`);
  } catch (err) {
    console.error("Error:", err.message);
  } finally {
    await client.end();
  }
}

clearBindings();
