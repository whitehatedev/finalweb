import fs from 'node:fs/promises';
import path from 'node:path';
import { createPool } from './index.ts';

let customerSchemaEnsured = false;

export async function ensureCustomerManagementSchema(): Promise<void> {
  if (customerSchemaEnsured) return;
  const pool = createPool();
  if (!pool) {
    customerSchemaEnsured = true;
    return;
  }

  try {
    const sqlPath = path.resolve(process.cwd(), 'supabase/customer_management_table.sql');
    const sqlText = await fs.readFile(sqlPath, 'utf8');
    await pool.query(sqlText);
    customerSchemaEnsured = true;
  } catch (err) {
    console.warn('Customer management DDL bootstrap warning:', (err as Error).message);
  }
}
