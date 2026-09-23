import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { readFile } from 'node:fs/promises';

const identifier = value => { if (!/^[a-z_]+$/.test(value)) throw Error('Invalid identifier'); return '"' + value + '"'; };
export async function createIdentityDb({ beforeUpgrade } = {}) {
  const pg = new PGlite({ extensions: { pgcrypto } });
  await pg.exec('create role anon; create role authenticated; create role service_role bypassrls;');
  for (const file of ['202609180001_identity.sql', '202609190001_fix_private_schema_permissions.sql']) {
    await pg.exec(await readFile(new URL('../../supabase/migrations/' + file, import.meta.url), 'utf8'));
  }
  if (beforeUpgrade) await beforeUpgrade(pg);
  await pg.exec(await readFile(new URL('../../supabase/migrations/202609230001_verified_identity.sql', import.meta.url), 'utf8'));
  await pg.exec(await readFile(new URL('../../supabase/migrations/202609230002_member_writing.sql', import.meta.url), 'utf8'));
  await pg.exec(await readFile(new URL('../../supabase/migrations/202609230003_member_navigation.sql', import.meta.url), 'utf8'));
  // Exercise the actual service_role grants rather than the database owner.
  await pg.exec('set role service_role');
  const execute = async (sql, args) => {
    try { const result = await pg.query(sql, args); return { data: result.rows, error: null }; }
    catch (error) { return { data: null, error: { code: error.code, message: error.message } }; }
  };
  const db = {
    async rpc(name, args) {
      const values = Object.values(args);
      const params = Object.keys(args).map((key, i) => `${identifier(key)} => $${i + 1}`).join(', ');
      const result = await execute(`select private.${identifier(name)}(${params}) as result`, values);
      return { data: result.data?.[0]?.result ?? null, error: result.error };
    },
    from(table) {
      const tableName = `private.${identifier(table)}`;
      let operation = 'select', record, filters = [], fields = '*';
      const query = {
        select(value = '*') { fields = value; return query; },
        insert(value) { operation = 'insert'; record = value; return query; },
        update(value) { operation = 'update'; record = value; return query; },
        eq(column, value) { filters.push([column, value]); return query; },
        async run(single = false) {
          let args = [], sql;
          const columns = fields === '*' ? '*' : fields.split(',').map(s => identifier(s.trim())).join(',');
          if (operation === 'insert') {
            const keys = Object.keys(record); args = Object.values(record);
            sql = `insert into ${tableName} (${keys.map(identifier)}) values (${args.map((_, i) => '$' + (i + 1))}) returning *`;
          } else {
            sql = operation === 'select' ? `select ${columns} from ${tableName}` : `update ${tableName} set ` + Object.entries(record).map(([key, value]) => { args.push(value); return `${identifier(key)} = $${args.length}`; }).join(',');
            if (filters.length) sql += ' where ' + filters.map(([key, value]) => { args.push(value); return `${identifier(key)} = $${args.length}`; }).join(' and ');
            if (operation === 'update') sql += ' returning *';
          }
          // PostgreSQL parameters store only the explicit proposal, never request headers.
          const result = await execute(sql, args.map(v => v && typeof v === 'object' ? JSON.stringify(v) : v));
          if (single && result.data) result.data = result.data[0] || null;
          return result;
        },
        maybeSingle() { return query.run(true); },
        then(resolve, reject) { return query.run().then(resolve, reject); },
      };
      return query;
    },
  };
  return { pg, db };
}
