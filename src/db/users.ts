import crypto from 'crypto';
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { createPool, db } from './index.ts';
import { adminSessions, customerAddresses, customers, users } from './schema.ts';
import { ensureCustomerManagementSchema } from './ensure-customer-mgmt.ts';
import { hashPassword, verifyPassword } from '../server/utils.ts';
import {
  createAnonServerSupabaseClient,
  getServiceRoleSupabaseClient,
} from '../lib/supabase-admin.ts';

const DEFAULT_ADMIN_EMAILS = ['info.nexustekfusion@gmail.com', 'info@nexustekfusion.in'];

export const ADMIN_ROLES_SET = new Set([
  'super_admin',
  'admin',
  'website_manager',
  'product_manager',
  'sales_manager',
  'project_manager',
  'engineer',
  'printing_operator',
  'inventory_manager',
  'accounts_manager',
  'support_manager',
  'support_staff',
]);

export class AuthActionError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'AuthActionError';
    this.statusCode = statusCode;
  }
}

export function isUuid(value?: string | null): boolean {
  return Boolean(
    value && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim())
  );
}

export function normalizeEmail(email?: string | null): string {
  return String(email || '').trim().toLowerCase();
}

export function normalizeMobile(mobile?: string | null): string {
  let cleaned = String(mobile || '').trim().replace(/[\s()-]+/g, '');
  if (/^\+91[6-9]\d{9}$/.test(cleaned)) {
    cleaned = cleaned.slice(3);
  } else if (/^91[6-9]\d{9}$/.test(cleaned)) {
    cleaned = cleaned.slice(2);
  }
  return cleaned;
}

const FALLBACK_SESSION_SECRET = crypto
  .createHash('sha256')
  .update(
    `ntf-session-v1-${
      process.env.DATABASE_URL ||
      process.env.SUPABASE_URL ||
      process.env.SQL_HOST ||
      'nexustekfusion-local'
    }`
  )
  .digest('hex');

function getSessionSecret(): string {
  return (
    process.env.ADMIN_SESSION_SECRET ||
    process.env.SESSION_SECRET ||
    FALLBACK_SESSION_SECRET
  );
}

function signSessionToken(rawToken: string): string {
  const sig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(rawToken)
    .digest('hex');
  return `${rawToken}.${sig}`;
}

function verifySignedSessionToken(signed: string): string | null {
  const parts = signed.split('.');
  if (parts.length !== 2) return null;
  const [rawToken, providedSig] = parts;
  if (!rawToken || !providedSig) return null;
  const expectedSig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(rawToken)
    .digest('hex');
  try {
    const a = Buffer.from(providedSig, 'hex');
    const b = Buffer.from(expectedSig, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return rawToken;
  } catch {
    return null;
  }
}

export function isBootstrapAdminEmail(email: string): boolean {
  const configured = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  const envInitial = (process.env.INITIAL_ADMIN_EMAIL || '').trim().toLowerCase();
  if (envInitial) configured.push(envInitial);
  const allAdmins = new Set([...DEFAULT_ADMIN_EMAILS, ...configured]);
  return allAdmins.has(email.trim().toLowerCase());
}

export async function ensureInitialAdminUser(): Promise<void> {
  const email = (process.env.INITIAL_ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.INITIAL_ADMIN_PASSWORD || '';
  const name = (process.env.INITIAL_ADMIN_NAME || 'Super Admin').trim();

  if (!email || !password) return;

  try {
    const existing = await db
      .select()
      .from(users)
      .where(and(sql`lower(${users.email}) = ${email}`, isNull(users.deletedAt)))
      .limit(1);

    if (existing.length > 0) {
      const current = existing[0];
      if (!current.passwordHash && !current.authUserId) {
        const serviceClient = getServiceRoleSupabaseClient();
        if (serviceClient) {
          const { data: created } = await serviceClient.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
            user_metadata: { full_name: current.fullName || name },
          });
          if (created?.user?.id) {
            await db
              .update(users)
              .set({
                authUserId: created.user.id,
                fullName: current.fullName || name,
                role: 'super_admin',
                isActive: true,
                accountStatus: 'Active',
                emailVerified: true,
                emailConfirmedAt: created.user.email_confirmed_at || new Date().toISOString(),
                updatedAt: new Date(),
              })
              .where(eq(users.id, current.id));
            return;
          }
        }
        await db
          .update(users)
          .set({
            fullName: current.fullName || name,
            role: 'super_admin',
            passwordHash: hashPassword(password),
            isActive: true,
            updatedAt: new Date(),
          })
          .where(eq(users.id, current.id));
      } else if (current.role === 'customer') {
        await db
          .update(users)
          .set({ role: 'super_admin', updatedAt: new Date() })
          .where(eq(users.id, current.id));
      }
      return;
    }

    const serviceClient = getServiceRoleSupabaseClient();
    if (serviceClient) {
      const { data: created } = await serviceClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: name },
      });
      if (created?.user?.id) {
        await db
          .insert(users)
          .values({
            uid: created.user.id,
            authUserId: created.user.id,
            email,
            fullName: name,
            role: 'super_admin',
            passwordHash: null,
            emailVerified: true,
            emailConfirmedAt: created.user.email_confirmed_at || new Date().toISOString(),
            accountStatus: 'Active',
            isActive: true,
          })
          .onConflictDoUpdate({
            target: users.uid,
            set: {
              authUserId: created.user.id,
              role: 'super_admin',
              fullName: name,
              accountStatus: 'Active',
              isActive: true,
              updatedAt: new Date(),
            },
          });
        return;
      }
    }

    await db.insert(users).values({
      uid: `admin_${crypto.randomBytes(6).toString('hex')}`,
      email,
      fullName: name,
      role: 'super_admin',
      passwordHash: hashPassword(password),
      isActive: true,
    });
  } catch (error) {
    console.error('Failed to ensure initial admin user:', error);
  }
}

export async function getAdminSetupStatus() {
  const activeAdmins = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.isActive, true), isNull(users.deletedAt), sql`${users.role} <> 'customer'`));
  const hasPasswordAdmin = activeAdmins.length > 0;
  const envConfigured = Boolean(process.env.INITIAL_ADMIN_EMAIL && process.env.INITIAL_ADMIN_PASSWORD);
  return {
    configured: hasPasswordAdmin || envConfigured,
    hasPasswordAdmin,
    envConfigured,
  };
}

async function migrateLegacyUserToSupabaseAuth(
  user: typeof users.$inferSelect,
  plainPassword: string
): Promise<typeof users.$inferSelect> {
  if (user.authUserId) return user;
  const serviceClient = getServiceRoleSupabaseClient();
  if (!serviceClient) return user;

  try {
    const cleanEmail = normalizeEmail(user.email);
    const { data, error } = await serviceClient.auth.admin.createUser({
      email: cleanEmail,
      password: plainPassword,
      email_confirm: true,
      user_metadata: {
        full_name: user.fullName || '',
        phone: user.mobile || '',
        company_or_college: user.companyOrCollege || '',
      },
    });

    if (error || !data?.user?.id) {
      return user;
    }

    const authId = data.user.id;
    const shouldUpgradeUid = !isUuid(user.uid) && (user.uid.startsWith('usr_') || user.uid.startsWith('guest_'));
    const [updated] = await db
      .update(users)
      .set({
        authUserId: authId,
        uid: shouldUpgradeUid ? authId : user.uid,
        passwordHash: null,
        emailVerified: true,
        emailConfirmedAt: user.emailConfirmedAt || data.user.email_confirmed_at || new Date().toISOString(),
        lastLoginAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(users.id, user.id))
      .returning();

    return updated || user;
  } catch {
    return user;
  }
}

export async function verifyAdminCredentials(email: string, password: string) {
  const cleanEmail = normalizeEmail(email);
  if (!cleanEmail || !password) return null;

  // 1. Try Supabase Auth first if the admin exists in Supabase Auth
  const anonClient = createAnonServerSupabaseClient();
  if (anonClient) {
    const { data, error } = await anonClient.auth.signInWithPassword({
      email: cleanEmail,
      password,
    });
    if (!error && data?.user?.id) {
      const [dbRow] = await db
        .select()
        .from(users)
        .where(
          and(
            isNull(users.deletedAt),
            or(
              eq(users.authUserId, data.user.id),
              eq(users.uid, data.user.id),
              sql`lower(${users.email}) = ${cleanEmail}`
            )
          )
        )
        .limit(1);

      if (dbRow && dbRow.isActive && dbRow.accountStatus === 'Active' && ADMIN_ROLES_SET.has(dbRow.role)) {
        const [updated] = await db
          .update(users)
          .set({ authUserId: data.user.id, lastLoginAt: new Date(), updatedAt: new Date() })
          .where(eq(users.id, dbRow.id))
          .returning();
        return updated || dbRow;
      }
      return null;
    }
  }

  // 2. Fallback to legacy pre-migration passwordHash for existing admin accounts (e.g. info@nexustekfusion.in)
  const rows = await db
    .select()
    .from(users)
    .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
    .limit(1);

  const user = rows[0];
  if (!user || !user.isActive || user.accountStatus !== 'Active' || !ADMIN_ROLES_SET.has(user.role)) {
    return null;
  }
  if (!user.passwordHash || !verifyPassword(password, user.passwordHash)) {
    return null;
  }

  return await migrateLegacyUserToSupabaseAuth(user, password);
}

export async function signInCustomerWithSupabaseAuth(email: string, password: string): Promise<{
  user: typeof users.$inferSelect;
  supabaseSession: { access_token: string; refresh_token: string } | null;
}> {
  const cleanEmail = normalizeEmail(email);
  if (!cleanEmail || !password) {
    throw new AuthActionError('Email and password are required.', 400);
  }

  await ensureCustomerManagementSchema();

  // 1. Primary authentication against dedicated web_platform.customers table
  const [custRow] = await db
    .select()
    .from(customers)
    .where(and(sql`lower(${customers.email}) = ${cleanEmail}`, isNull(customers.deletedAt)))
    .limit(1);

  if (custRow && custRow.passwordHash) {
    if (!verifyPassword(password, custRow.passwordHash)) {
      throw new AuthActionError('Invalid email or password.', 401);
    }
    if (custRow.accountStatus !== 'Active') {
      throw new AuthActionError(
        `Your account is currently ${custRow.accountStatus || 'inactive'}. Please contact support.`,
        403
      );
    }

    const now = new Date();
    await db
      .update(customers)
      .set({ lastLoginAt: now, updatedAt: now })
      .where(eq(customers.id, custRow.id));

    let linkedUser: typeof users.$inferSelect | undefined;
    if (custRow.userId) {
      const [u] = await db
        .select()
        .from(users)
        .where(and(eq(users.id, custRow.userId), isNull(users.deletedAt)))
        .limit(1);
      linkedUser = u;
    }
    if (!linkedUser) {
      const [byEmail] = await db
        .select()
        .from(users)
        .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
        .limit(1);
      linkedUser = byEmail;
    }

    if (!linkedUser) {
      const [createdLink] = await db
        .insert(users)
        .values({
          uid: custRow.customerId,
          authUserId: null,
          email: cleanEmail,
          fullName: custRow.fullName,
          mobile: custRow.phoneNumber,
          companyOrCollege: custRow.companyOrCollege,
          fullAddress: custRow.fullAddress,
          city: custRow.city,
          state: custRow.state,
          pinCode: custRow.pinCode,
          role: 'customer',
          passwordHash: custRow.passwordHash,
          accountStatus: custRow.accountStatus,
          isActive: custRow.accountStatus === 'Active',
          lastLoginAt: now,
        })
        .returning();
      linkedUser = createdLink;
      await db
        .update(customers)
        .set({ userId: createdLink.id, updatedAt: now })
        .where(eq(customers.id, custRow.id));
    } else {
      const [updatedUser] = await db
        .update(users)
        .set({ lastLoginAt: now, updatedAt: now })
        .where(eq(users.id, linkedUser.id))
        .returning();
      linkedUser = updatedUser || linkedUser;
    }

    return { user: linkedUser, supabaseSession: null };
  }

  // 2. Check web_platform.users local password_hash (for admin-migrated or staff accounts)
  const rows = await db
    .select()
    .from(users)
    .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
    .limit(1);

  const localUser = rows[0];
  if (localUser && localUser.passwordHash && verifyPassword(password, localUser.passwordHash)) {
    if (!localUser.isActive || localUser.accountStatus !== 'Active') {
      throw new AuthActionError(
        `Your account is currently ${localUser.accountStatus || 'inactive'}. Please contact support.`,
        403
      );
    }
    const [updated] = await db
      .update(users)
      .set({ lastLoginAt: new Date(), updatedAt: new Date() })
      .where(eq(users.id, localUser.id))
      .returning();
    return { user: updated || localUser, supabaseSession: null };
  }

  // 3. Fallback for pre-existing OAuth/Supabase-Auth-only users without a local password hash
  const anonClient = createAnonServerSupabaseClient();
  if (anonClient) {
    const { data, error } = await anonClient.auth.signInWithPassword({
      email: cleanEmail,
      password,
    });
    if (!error && data?.user) {
      const meta = data.user.user_metadata || {};
      const synced = await getOrCreateUser(
        data.user.id,
        data.user.email || cleanEmail,
        String(meta.full_name || meta.name || '').trim(),
        {
          phone: String(data.user.phone || meta.phone || '').trim(),
          companyOrCollege: String(meta.company_or_college || '').trim(),
          emailConfirmedAt: data.user.email_confirmed_at ? String(data.user.email_confirmed_at) : '',
          phoneConfirmedAt: data.user.phone_confirmed_at ? String(data.user.phone_confirmed_at) : '',
        }
      );

      if (!synced.isActive || synced.accountStatus !== 'Active' || synced.deletedAt) {
        throw new AuthActionError(
          `Your account is currently ${synced.accountStatus || 'inactive'}. Please contact support.`,
          403
        );
      }

      return {
        user: synced,
        supabaseSession: data.session
          ? {
              access_token: data.session.access_token,
              refresh_token: data.session.refresh_token,
            }
          : null,
      };
    }
  }

  throw new AuthActionError('Invalid email or password.', 401);
}

export async function verifyUserCredentials(email: string, password: string) {
  try {
    const result = await signInCustomerWithSupabaseAuth(email, password);
    return result.user;
  } catch {
    return null;
  }
}

export async function registerCustomerWithSupabaseAuth(input: {
  email: string;
  password: string;
  fullName: string;
  mobile?: string;
  companyOrCollege?: string;
  fullAddress?: string;
  city?: string;
  state?: string;
  pinCode?: string;
}): Promise<{
  customer: typeof customers.$inferSelect;
  user: typeof users.$inferSelect;
  supabaseSession: null;
}> {
  await ensureCustomerManagementSchema();

  const cleanEmail = normalizeEmail(input.email);
  const cleanFullName = String(input.fullName || '').trim();
  const cleanMobile = normalizeMobile(input.mobile);
  const cleanCompany = String(input.companyOrCollege || '').trim();
  const cleanAddress = String(input.fullAddress || '').trim();
  const cleanCity = String(input.city || '').trim();
  const cleanState = String(input.state || '').trim();
  const cleanPinCode = String(input.pinCode || '').trim();

  if (!cleanFullName || cleanFullName.length < 2) {
    throw new AuthActionError('Full name is required.', 400);
  }
  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    throw new AuthActionError('Please enter a valid email address.', 400);
  }
  if (!input.password || input.password.length < 8) {
    throw new AuthActionError('Password must be at least 8 characters long.', 400);
  }
  if (cleanMobile && !/^\+?\d{10,15}$/.test(cleanMobile)) {
    throw new AuthActionError('Please enter a valid 10-digit phone number.', 400);
  }
  if (cleanPinCode && !/^[0-9]{4,10}$/.test(cleanPinCode)) {
    throw new AuthActionError('PIN Code must be 4 to 10 numeric digits.', 400);
  }

  // 1. Check duplicate active email & mobile across dedicated web_platform.customers and web_platform.users
  const [existingCustomerEmail] = await db
    .select({ id: customers.id })
    .from(customers)
    .where(and(sql`lower(${customers.email}) = ${cleanEmail}`, isNull(customers.deletedAt)))
    .limit(1);

  const [existingUserEmail] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
    .limit(1);

  if (existingCustomerEmail || existingUserEmail) {
    throw new AuthActionError('An account with this email already exists. Please sign in instead.', 409);
  }

  if (cleanMobile) {
    const [existingCustomerMobile] = await db
      .select({ id: customers.id })
      .from(customers)
      .where(and(eq(customers.phoneNumber, cleanMobile), isNull(customers.deletedAt)))
      .limit(1);

    const [existingUserMobile] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.mobile, cleanMobile), isNull(users.deletedAt)))
      .limit(1);

    if (existingCustomerMobile || existingUserMobile) {
      throw new AuthActionError(
        'This phone number is already registered with an existing account. Please use a different number or sign in.',
        409
      );
    }
  }

  // 2. Hash password locally (no Supabase Auth account creation)
  const hashed = hashPassword(input.password);
  const now = new Date();
  const role = isBootstrapAdminEmail(cleanEmail) ? 'super_admin' : 'customer';

  // 3. Insert directly into dedicated web_platform.customers table
  //    PostgreSQL sequence/trigger auto-generates unique customer_id (NTF-CUST-XXXX),
  //    registration_date, and account_status = 'Active'.
  let createdCustomer: typeof customers.$inferSelect;
  try {
    const [insertedCust] = await db
      .insert(customers)
      .values({
        fullName: cleanFullName,
        email: cleanEmail,
        phoneNumber: cleanMobile,
        companyOrCollege: cleanCompany,
        fullAddress: cleanAddress,
        city: cleanCity,
        state: cleanState,
        pinCode: cleanPinCode,
        passwordHash: hashed,
        accountStatus: 'Active',
        registrationDate: now,
        lastLoginAt: now,
      })
      .returning();
    createdCustomer = insertedCust;
  } catch (custErr: any) {
    const pgCode = custErr?.code || custErr?.cause?.code;
    const detail = String(custErr?.detail || custErr?.cause?.detail || custErr?.message || '');
    if (pgCode === '23505') {
      if (detail.includes('phone')) {
        throw new AuthActionError('This phone number is already registered.', 409);
      }
      throw new AuthActionError('An account with this email already exists.', 409);
    }
    throw new AuthActionError(custErr?.message || 'Failed to save registration record.', 500);
  }

  // 4. Create linked web_platform.users profile & default customer_addresses row so checkout/orders/sessions work seamlessly
  let linkedUser: typeof users.$inferSelect;
  try {
    const [insertedUser] = await db
      .insert(users)
      .values({
        uid: createdCustomer.customerId,
        authUserId: null,
        email: cleanEmail,
        fullName: cleanFullName,
        mobile: cleanMobile,
        companyOrCollege: cleanCompany,
        fullAddress: cleanAddress,
        city: cleanCity,
        state: cleanState,
        pinCode: cleanPinCode,
        role,
        passwordHash: hashed,
        emailVerified: false,
        phoneVerified: false,
        emailConfirmedAt: '',
        phoneConfirmedAt: '',
        accountStatus: 'Active',
        isActive: true,
        lastLoginAt: now,
      })
      .returning();

    linkedUser = insertedUser;

    await db
      .update(customers)
      .set({ userId: insertedUser.id, updatedAt: now })
      .where(eq(customers.id, createdCustomer.id));

    createdCustomer = { ...createdCustomer, userId: insertedUser.id };

    if (cleanAddress || cleanCity || cleanState || cleanPinCode) {
      await db.insert(customerAddresses).values({
        userId: insertedUser.id,
        label: 'Primary',
        addressType: 'both',
        fullName: cleanFullName,
        mobile: cleanMobile,
        houseFlat: cleanAddress || cleanCity || 'Primary Address',
        streetArea: '',
        landmark: '',
        city: cleanCity,
        district: cleanCity,
        state: cleanState,
        pinCode: cleanPinCode,
        country: 'India',
        isDefault: true,
      });
    }
  } catch (linkErr: any) {
    // Rollback customer row if user link creation fails
    await db.delete(customers).where(eq(customers.id, createdCustomer.id)).catch(() => {});
    throw new AuthActionError(linkErr?.message || 'Failed to initialize customer account session.', 500);
  }

  return { customer: createdCustomer, user: linkedUser, supabaseSession: null };
}

export async function createAdminSession(userId: number, userAgent = '') {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await db.insert(adminSessions).values({
    tokenHash,
    userId,
    userAgent: userAgent.slice(0, 240),
    expiresAt,
  });

  return {
    cookieValue: signSessionToken(rawToken),
    expiresAt,
  };
}

export async function getUserBySessionToken(signedToken: string) {
  const rawToken = verifySignedSessionToken(signedToken);
  if (!rawToken) return null;
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  const rows = await db
    .select({ user: users })
    .from(adminSessions)
    .innerJoin(users, eq(adminSessions.userId, users.id))
    .where(
      and(
        eq(adminSessions.tokenHash, tokenHash),
        gt(adminSessions.expiresAt, new Date()),
        isNull(users.deletedAt)
      )
    )
    .limit(1);

  const found = rows[0]?.user;
  if (!found || !found.isActive || found.accountStatus !== 'Active') return null;
  return found;
}

export async function deleteAdminSession(signedToken: string) {
  const rawToken = verifySignedSessionToken(signedToken);
  if (!rawToken) return;
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  await db.delete(adminSessions).where(eq(adminSessions.tokenHash, tokenHash));
}

export async function updateUserPassword(userId: number, newPassword: string) {
  const [userRow] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!userRow) throw new AuthActionError('User not found.', 404);

  const serviceClient = getServiceRoleSupabaseClient();
  if (serviceClient) {
    let targetAuthId = userRow.authUserId || (isUuid(userRow.uid) ? userRow.uid : null);
    if (targetAuthId) {
      const { error } = await serviceClient.auth.admin.updateUserById(targetAuthId, {
        password: newPassword,
      });
      if (error) {
        throw new AuthActionError(error.message || 'Failed to update password in Supabase Auth.', 400);
      }
    } else {
      const { data: created, error } = await serviceClient.auth.admin.createUser({
        email: normalizeEmail(userRow.email),
        password: newPassword,
        email_confirm: true,
        user_metadata: {
          full_name: userRow.fullName || '',
          phone: userRow.mobile || '',
          company_or_college: userRow.companyOrCollege || '',
        },
      });
      if (error || !created?.user?.id) {
        throw new AuthActionError(error?.message || 'Failed to sync password with Supabase Auth.', 400);
      }
      targetAuthId = created.user.id;
    }

    await db
      .update(users)
      .set({
        authUserId: targetAuthId,
        passwordHash: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
    return;
  }

  await db
    .update(users)
    .set({
      passwordHash: hashPassword(newPassword),
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));
}

export async function getOrCreateUser(
  uid: string,
  email: string,
  fullName?: string,
  extra?: {
    phone?: string;
    companyOrCollege?: string;
    emailConfirmedAt?: string;
    phoneConfirmedAt?: string;
  }
) {
  try {
    const cleanEmail = normalizeEmail(email);
    const authUuid = isUuid(uid) ? uid : null;
    const incomingPhone = normalizeMobile(extra?.phone);
    const incomingCompany = String(extra?.companyOrCollege || '').trim();
    const shouldBeSuperAdmin = cleanEmail ? isBootstrapAdminEmail(cleanEmail) : false;
    const emailVerified = Boolean(extra?.emailConfirmedAt);
    const phoneVerified = Boolean(extra?.phoneConfirmedAt);

    // Avoid colliding with another user's unique mobile
    let safeIncomingPhone = incomingPhone;
    if (safeIncomingPhone) {
      const phoneConflict = await db
        .select({ id: users.id, uid: users.uid, authUserId: users.authUserId, email: users.email })
        .from(users)
        .where(and(eq(users.mobile, safeIncomingPhone), isNull(users.deletedAt)))
        .limit(1);
      if (
        phoneConflict.length > 0 &&
        phoneConflict[0].uid !== uid &&
        phoneConflict[0].authUserId !== authUuid &&
        normalizeEmail(phoneConflict[0].email) !== cleanEmail
      ) {
        safeIncomingPhone = '';
      }
    }

    const existing = await db
      .select()
      .from(users)
      .where(
        and(
          isNull(users.deletedAt),
          authUuid ? or(eq(users.authUserId, authUuid), eq(users.uid, uid)) : eq(users.uid, uid)
        )
      )
      .limit(1);

    let resultUser: typeof users.$inferSelect;

    if (existing.length > 0) {
      const current = existing[0];
      const nextRole = shouldBeSuperAdmin && current.role === 'customer' ? 'super_admin' : current.role;
      const shouldUpgradeUid = Boolean(
        authUuid && !isUuid(current.uid) && (current.uid.startsWith('usr_') || current.uid.startsWith('guest_'))
      );
      const [updated] = await db
        .update(users)
        .set({
          authUserId: authUuid || current.authUserId,
          uid: shouldUpgradeUid && authUuid ? authUuid : current.uid,
          email: cleanEmail || current.email,
          fullName: current.fullName || fullName || '',
          mobile: current.mobile || safeIncomingPhone,
          companyOrCollege: current.companyOrCollege || incomingCompany,
          emailVerified: current.emailVerified || emailVerified,
          phoneVerified: current.phoneVerified || phoneVerified,
          emailConfirmedAt: extra?.emailConfirmedAt || current.emailConfirmedAt,
          phoneConfirmedAt: extra?.phoneConfirmedAt || current.phoneConfirmedAt,
          role: nextRole,
          lastLoginAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(users.id, current.id))
        .returning();
      resultUser = updated;
    } else if (cleanEmail) {
      const byEmail = await db
        .select()
        .from(users)
        .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
        .limit(1);

      if (byEmail.length > 0) {
        const current = byEmail[0];
        const nextRole = shouldBeSuperAdmin && current.role === 'customer' ? 'super_admin' : current.role;
        const shouldUpgradeUid = Boolean(
          authUuid && (!isUuid(current.uid) && (current.uid.startsWith('usr_') || current.uid.startsWith('guest_')))
        );
        const [linked] = await db
          .update(users)
          .set({
            uid: shouldUpgradeUid && authUuid ? authUuid : current.uid,
            authUserId: authUuid || current.authUserId,
            fullName: current.fullName || fullName || '',
            mobile: current.mobile || safeIncomingPhone,
            companyOrCollege: current.companyOrCollege || incomingCompany,
            emailVerified: current.emailVerified || emailVerified,
            phoneVerified: current.phoneVerified || phoneVerified,
            emailConfirmedAt: extra?.emailConfirmedAt || current.emailConfirmedAt,
            phoneConfirmedAt: extra?.phoneConfirmedAt || current.phoneConfirmedAt,
            role: nextRole,
            lastLoginAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(users.id, current.id))
          .returning();
        resultUser = linked;
      } else {
        const [inserted] = await db
          .insert(users)
          .values({
            uid,
            authUserId: authUuid,
            email: cleanEmail,
            fullName: fullName || '',
            mobile: safeIncomingPhone,
            companyOrCollege: incomingCompany,
            passwordHash: null,
            emailVerified,
            phoneVerified,
            emailConfirmedAt: extra?.emailConfirmedAt || '',
            phoneConfirmedAt: extra?.phoneConfirmedAt || '',
            role: shouldBeSuperAdmin ? 'super_admin' : 'customer',
            accountStatus: 'Active',
            isActive: true,
            lastLoginAt: new Date(),
          })
          .onConflictDoUpdate({
            target: users.uid,
            set: {
              authUserId: authUuid,
              email: cleanEmail,
              mobile: safeIncomingPhone,
              companyOrCollege: incomingCompany,
              emailVerified,
              phoneVerified,
              lastLoginAt: new Date(),
              updatedAt: new Date(),
            },
          })
          .returning();
        resultUser = inserted;
      }
    } else {
      const [inserted] = await db
        .insert(users)
        .values({
          uid,
          authUserId: authUuid,
          email: cleanEmail,
          fullName: fullName || '',
          mobile: safeIncomingPhone,
          companyOrCollege: incomingCompany,
          passwordHash: null,
          emailVerified,
          phoneVerified,
          emailConfirmedAt: extra?.emailConfirmedAt || '',
          phoneConfirmedAt: extra?.phoneConfirmedAt || '',
          role: 'customer',
          accountStatus: 'Active',
          isActive: true,
          lastLoginAt: new Date(),
        })
        .onConflictDoUpdate({
          target: users.uid,
          set: { authUserId: authUuid, email: cleanEmail, lastLoginAt: new Date(), updatedAt: new Date() },
        })
        .returning();
      resultUser = inserted;
    }

    import('../server/supabase-ecommerce.ts')
      .then(({ syncCustomerProfileToSupabase }) =>
        syncCustomerProfileToSupabase({
          uid: resultUser.uid,
          email: resultUser.email,
          fullName: resultUser.fullName,
          mobile: resultUser.mobile,
          companyOrCollege: resultUser.companyOrCollege,
          role: resultUser.role,
          emailVerified: resultUser.emailVerified,
          phoneVerified: resultUser.phoneVerified,
          emailConfirmedAt: resultUser.emailConfirmedAt,
          phoneConfirmedAt: resultUser.phoneConfirmedAt,
        })
      )
      .catch(() => {});

    return resultUser;
  } catch (error) {
    console.error('Failed to upsert user:', error);
    throw new Error('Failed to synchronize user account.', { cause: error });
  }
}

export async function getUserByUid(uid: string) {
  try {
    const rows = await db
      .select()
      .from(users)
      .where(and(eq(users.uid, uid), isNull(users.deletedAt)))
      .limit(1);
    return rows[0] || null;
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to retrieve user record.', { cause: error });
  }
}
