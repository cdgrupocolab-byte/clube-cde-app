const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      password_hash TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      source TEXT NOT NULL DEFAULT 'manual',
      hubla_invoice_id TEXT,
      set_password_token TEXT,
      token_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS processed_webhooks (
      id TEXT PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS webhook_log (
      id SERIAL PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      token_valid BOOLEAN,
      type TEXT,
      raw JSONB
    );
  `);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS avatar_url TEXT;`);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS offer TEXT;`);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS seeking TEXT;`);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS niche TEXT;`);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS city TEXT;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS mural_posts (
      id SERIAL PRIMARY KEY,
      member_email TEXT NOT NULL,
      tipo TEXT NOT NULL,
      text TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'aberto',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, init };
