import crypto from 'crypto';
import { Router } from 'express';
import { and, desc, eq, isNull, ne, or, sql } from 'drizzle-orm';
import { db } from '../../db/index.ts';
import { ensureCustomerManagementSchema } from '../../db/ensure-customer-mgmt.ts';
import {
  adminSessions,
  auditLogs,
  customerAddresses,
  customers,
  droneRepairBookings,
  invoices,
  payments,
  pcbEnquiries,
  printingOrders,
  productEnquiries,
  projectEnquiries,
  projects,
  storeOrders,
  supportTickets,
  users,
} from '../../db/schema.ts';
import { normalizeEmail, normalizeMobile } from '../../db/users.ts';
import { AuthRequest, requireAdmin } from '../../middleware/auth.ts';
import { hashPassword, logAudit } from '../utils.ts';

export const adminCustomersRouter = Router();

const CUSTOMER_MANAGER_ROLES = [
  'super_admin',
  'admin',
  'sales_manager',
  'support_manager',
  'support_staff',
  'accounts_manager',
  'project_manager',
];

const VALID_ACCOUNT_STATUSES = new Set(['Active', 'Suspended', 'Deactivated']);

adminCustomersRouter.use(requireAdmin(CUSTOMER_MANAGER_ROLES));

function formatCustomerCode(id: number): string {
  return `NTF-CUST-${String(id).padStart(4, '0')}`;
}

function escapeXml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function escapeCsvCell(value: unknown): string {
  let s = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toSafeCsv(headers: string[], rows: Array<Array<unknown>>): string {
  return [
    headers.map(escapeCsvCell).join(','),
    ...rows.map((r) => r.map(escapeCsvCell).join(',')),
  ].join('\n');
}

function toExcelSpreadsheetXml(
  sheetName: string,
  headers: string[],
  rows: Array<Array<unknown>>
): string {
  const safeSheet = escapeXml(sheetName).slice(0, 31) || 'Customers';
  const headerXml = `<Row>${headers
    .map((h) => `<Cell ss:StyleID="Header"><Data ss:Type="String">${escapeXml(h)}</Data></Cell>`)
    .join('')}</Row>`;

  const bodyXml = rows
    .map(
      (r) =>
        `<Row>${r
          .map((cell) => {
            if (typeof cell === 'number' && Number.isFinite(cell)) {
              return `<Cell><Data ss:Type="Number">${cell}</Data></Cell>`;
            }
            return `<Cell><Data ss:Type="String">${escapeXml(cell)}</Data></Cell>`;
          })
          .join('')}</Row>`
    )
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Styles>
  <Style ss:ID="Default" ss:Name="Normal">
   <Font ss:FontName="Calibri" ss:Size="10" ss:Color="#123B5D"/>
  </Style>
  <Style ss:ID="Header">
   <Font ss:FontName="Calibri" ss:Size="10" ss:Bold="1" ss:Color="#FFFFFF"/>
   <Interior ss:Color="#123B5D" ss:Pattern="Solid"/>
  </Style>
 </Styles>
 <Worksheet ss:Name="${safeSheet}">
  <Table>
   ${headerXml}
   ${bodyXml}
  </Table>
 </Worksheet>
</Workbook>`;
}

export interface EnrichedCustomerRow {
  id: number;
  userId: number | null;
  customerCode: string;
  uid: string;
  fullName: string;
  email: string;
  mobile: string;
  companyOrCollege: string;
  fullAddress: string;
  city: string;
  state: string;
  pinCode: string;
  role: string;
  accountStatus: string;
  statusReason: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  isActive: boolean;
  lastLoginAt: string | null;
  registrationDate: string;
  createdAt: string;
  updatedAt: string;
  addressesCount: number;
  ordersCount: number;
  projectsCount: number;
  enquiriesCount: number;
  totalSpentInr: number;
}

async function buildEnrichedCustomers(query?: {
  search?: string;
  status?: string;
  state?: string;
  role?: string;
  sortBy?: string;
  sortDir?: string;
}): Promise<{
  customers: EnrichedCustomerRow[];
  summary: {
    total: number;
    active: number;
    suspended: number;
    deactivated: number;
    totalRevenueInr: number;
  };
  filterOptions: {
    states: string[];
    roles: string[];
  };
}> {
  await ensureCustomerManagementSchema();

  const [
    allCustomers,
    allUsers,
    allAddresses,
    allStoreOrders,
    allPrintOrders,
    allProjectEnquiries,
    allProductEnquiries,
    allPayments,
  ] = await Promise.all([
    db
      .select()
      .from(customers)
      .where(isNull(customers.deletedAt))
      .orderBy(desc(customers.registrationDate), desc(customers.id)),
    db.select().from(users).where(isNull(users.deletedAt)),
    db
      .select()
      .from(customerAddresses)
      .orderBy(desc(customerAddresses.isDefault), desc(customerAddresses.id)),
    db
      .select({
        id: storeOrders.id,
        userId: storeOrders.userId,
        totalInr: storeOrders.totalInr,
        paymentStatus: storeOrders.paymentStatus,
      })
      .from(storeOrders)
      .where(eq(storeOrders.isDeleted, false)),
    db
      .select({
        id: printingOrders.id,
        userId: printingOrders.userId,
        totalInr: printingOrders.totalInr,
        paymentStatus: printingOrders.paymentStatus,
      })
      .from(printingOrders),
    db
      .select({
        id: projectEnquiries.id,
        userId: projectEnquiries.userId,
        customerEmail: projectEnquiries.customerEmail,
      })
      .from(projectEnquiries)
      .where(eq(projectEnquiries.isDeleted, false)),
    db
      .select({
        id: productEnquiries.id,
        userId: productEnquiries.userId,
        email: productEnquiries.email,
      })
      .from(productEnquiries),
    db
      .select({
        id: payments.id,
        userId: payments.userId,
        amountInr: payments.amountInr,
        status: payments.status,
      })
      .from(payments),
  ]);

  const userById = new Map<number, typeof users.$inferSelect>();
  const userByEmail = new Map<string, typeof users.$inferSelect>();
  for (const u of allUsers) {
    userById.set(u.id, u);
    userByEmail.set(normalizeEmail(u.email), u);
  }

  const addressesByUser = new Map<number, typeof allAddresses>();
  for (const addr of allAddresses) {
    const arr = addressesByUser.get(addr.userId) || [];
    arr.push(addr);
    addressesByUser.set(addr.userId, arr);
  }

  const storeOrdersByUser = new Map<number, number>();
  for (const so of allStoreOrders) {
    storeOrdersByUser.set(so.userId, (storeOrdersByUser.get(so.userId) || 0) + 1);
  }

  const printOrdersByUser = new Map<number, number>();
  for (const po of allPrintOrders) {
    printOrdersByUser.set(po.userId, (printOrdersByUser.get(po.userId) || 0) + 1);
  }

  const spentByUser = new Map<number, number>();
  for (const pay of allPayments) {
    if (pay.userId && pay.status === 'verified') {
      spentByUser.set(pay.userId, (spentByUser.get(pay.userId) || 0) + (pay.amountInr || 0));
    }
  }

  const enrichedAll: EnrichedCustomerRow[] = allCustomers.map((c) => {
    const emailLower = normalizeEmail(c.email);
    const linkedUser =
      (c.userId ? userById.get(c.userId) : undefined) || userByEmail.get(emailLower);
    const resolvedUserId = linkedUser?.id ?? c.userId ?? null;

    const userAddresses = resolvedUserId ? addressesByUser.get(resolvedUserId) || [] : [];
    const defaultAddr = userAddresses[0];
    const addrLine = defaultAddr
      ? [defaultAddr.houseFlat, defaultAddr.streetArea, defaultAddr.landmark]
          .map((s) => String(s || '').trim())
          .filter(Boolean)
          .join(', ')
      : '';

    const fullAddress = String(c.fullAddress || '').trim() || linkedUser?.fullAddress || addrLine || '';
    const city = String(c.city || '').trim() || linkedUser?.city || defaultAddr?.city || '';
    const state = String(c.state || '').trim() || linkedUser?.state || defaultAddr?.state || '';
    const pinCode = String(c.pinCode || '').trim() || linkedUser?.pinCode || defaultAddr?.pinCode || '';

    const projectsCount = allProjectEnquiries.filter(
      (pe) =>
        (resolvedUserId !== null && pe.userId === resolvedUserId) ||
        normalizeEmail(pe.customerEmail) === emailLower
    ).length;

    const enquiriesCount = allProductEnquiries.filter(
      (de) =>
        (resolvedUserId !== null && de.userId === resolvedUserId) ||
        normalizeEmail(de.email) === emailLower
    ).length;

    const ordersCount = resolvedUserId
      ? (storeOrdersByUser.get(resolvedUserId) || 0) + (printOrdersByUser.get(resolvedUserId) || 0)
      : 0;
    const totalSpentInr = resolvedUserId ? spentByUser.get(resolvedUserId) || 0 : 0;
    const accountStatus = c.accountStatus || 'Active';
    const regIso = new Date(c.registrationDate || c.createdAt).toISOString();

    return {
      id: c.id,
      userId: resolvedUserId,
      customerCode: c.customerId || formatCustomerCode(c.id),
      uid: c.customerId || formatCustomerCode(c.id),
      fullName: c.fullName || '',
      email: c.email,
      mobile: c.phoneNumber || linkedUser?.mobile || '',
      companyOrCollege: c.companyOrCollege || linkedUser?.companyOrCollege || '',
      fullAddress,
      city,
      state,
      pinCode,
      role: linkedUser?.role || 'customer',
      accountStatus,
      statusReason: c.statusReason || '',
      emailVerified: Boolean(linkedUser?.emailVerified),
      phoneVerified: Boolean(linkedUser?.phoneVerified),
      isActive: accountStatus === 'Active',
      lastLoginAt: c.lastLoginAt
        ? new Date(c.lastLoginAt).toISOString()
        : linkedUser?.lastLoginAt
          ? new Date(linkedUser.lastLoginAt).toISOString()
          : null,
      registrationDate: regIso,
      createdAt: regIso,
      updatedAt: new Date(c.updatedAt).toISOString(),
      addressesCount: userAddresses.length,
      ordersCount,
      projectsCount,
      enquiriesCount,
      totalSpentInr,
    };
  });

  const states = Array.from(new Set(enrichedAll.map((c) => c.state).filter(Boolean))).sort((a, b) =>
    a.localeCompare(b)
  );
  const roles = Array.from(new Set(enrichedAll.map((c) => c.role).filter(Boolean))).sort();

  const summary = {
    total: enrichedAll.length,
    active: enrichedAll.filter((c) => c.accountStatus === 'Active').length,
    suspended: enrichedAll.filter((c) => c.accountStatus === 'Suspended').length,
    deactivated: enrichedAll.filter((c) => c.accountStatus === 'Deactivated').length,
    totalRevenueInr: enrichedAll.reduce((acc, c) => acc + c.totalSpentInr, 0),
  };

  const searchNeedle = String(query?.search || '').trim().toLowerCase();
  const statusFilter = String(query?.status || 'all').trim();
  const stateFilter = String(query?.state || 'all').trim();
  const roleFilter = String(query?.role || 'all').trim();
  const sortBy = String(query?.sortBy || 'created_at').trim();
  const sortDir = String(query?.sortDir || 'desc').trim().toLowerCase() === 'asc' ? 1 : -1;

  const filtered = enrichedAll.filter((c) => {
    if (statusFilter && statusFilter !== 'all' && c.accountStatus.toLowerCase() !== statusFilter.toLowerCase()) {
      return false;
    }
    if (stateFilter && stateFilter !== 'all' && c.state.toLowerCase() !== stateFilter.toLowerCase()) {
      return false;
    }
    if (roleFilter && roleFilter !== 'all' && c.role.toLowerCase() !== roleFilter.toLowerCase()) {
      return false;
    }
    if (searchNeedle) {
      const hay = [
        String(c.id),
        c.customerCode,
        c.fullName,
        c.email,
        c.mobile,
        c.companyOrCollege,
        c.fullAddress,
        c.city,
        c.state,
        c.pinCode,
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(searchNeedle)) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    let cmp = 0;
    switch (sortBy) {
      case 'id':
        cmp = a.customerCode.localeCompare(b.customerCode) || a.id - b.id;
        break;
      case 'full_name':
        cmp = a.fullName.localeCompare(b.fullName);
        break;
      case 'email':
        cmp = a.email.localeCompare(b.email);
        break;
      case 'city':
        cmp = a.city.localeCompare(b.city);
        break;
      case 'state':
        cmp = a.state.localeCompare(b.state);
        break;
      case 'account_status':
        cmp = a.accountStatus.localeCompare(b.accountStatus);
        break;
      case 'orders_count':
        cmp = a.ordersCount - b.ordersCount;
        break;
      case 'total_spent':
        cmp = a.totalSpentInr - b.totalSpentInr;
        break;
      case 'created_at':
      default:
        cmp = new Date(a.registrationDate).getTime() - new Date(b.registrationDate).getTime();
        break;
    }
    if (cmp === 0) cmp = a.id - b.id;
    return cmp * sortDir;
  });

  return {
    customers: filtered,
    summary,
    filterOptions: { states, roles },
  };
}

async function upsertDefaultCustomerAddress(
  userId: number,
  data: {
    fullName: string;
    mobile: string;
    fullAddress: string;
    city: string;
    state: string;
    pinCode: string;
  }
) {
  if (!data.fullAddress && !data.city && !data.state && !data.pinCode) return;

  const existingAddresses = await db
    .select()
    .from(customerAddresses)
    .where(eq(customerAddresses.userId, userId))
    .orderBy(desc(customerAddresses.isDefault), desc(customerAddresses.id))
    .limit(1);

  if (existingAddresses.length > 0) {
    const addr = existingAddresses[0];
    await db
      .update(customerAddresses)
      .set({
        fullName: data.fullName || addr.fullName,
        mobile: data.mobile || addr.mobile,
        houseFlat: data.fullAddress || addr.houseFlat,
        streetArea: data.fullAddress ? '' : addr.streetArea,
        city: data.city || addr.city,
        district: data.city || addr.district,
        state: data.state || addr.state,
        pinCode: data.pinCode || addr.pinCode,
        updatedAt: new Date(),
      })
      .where(eq(customerAddresses.id, addr.id));
  } else {
    await db.insert(customerAddresses).values({
      userId,
      label: 'Primary',
      addressType: 'both',
      fullName: data.fullName || 'Customer',
      mobile: data.mobile || '',
      houseFlat: data.fullAddress || data.city || 'Primary Address',
      streetArea: '',
      landmark: '',
      city: data.city || '',
      district: data.city || '',
      state: data.state || '',
      pinCode: data.pinCode || '',
      country: 'India',
      isDefault: true,
    });
  }
}

// 1. GET /api/admin/customers — List, search, filter, sort customers from web_platform.customers
adminCustomersRouter.get('/', async (req, res) => {
  try {
    const result = await buildEnrichedCustomers({
      search: String(req.query.search || ''),
      status: String(req.query.status || 'all'),
      state: String(req.query.state || 'all'),
      role: String(req.query.role || 'all'),
      sortBy: String(req.query.sortBy || 'created_at'),
      sortDir: String(req.query.sortDir || 'desc'),
    });
    res.json(result);
  } catch (error) {
    console.error('List customers error:', error);
    res.status(500).json({ error: 'Failed to load customers from Supabase.' });
  }
});

// 2. GET /api/admin/customers/export — Export filtered customer table to CSV or Excel (.xls)
adminCustomersRouter.get('/export', async (req, res) => {
  try {
    const format = String(req.query.format || 'csv').trim().toLowerCase();
    const { customers: exportList } = await buildEnrichedCustomers({
      search: String(req.query.search || ''),
      status: String(req.query.status || 'all'),
      state: String(req.query.state || 'all'),
      role: String(req.query.role || 'all'),
      sortBy: String(req.query.sortBy || 'created_at'),
      sortDir: String(req.query.sortDir || 'desc'),
    });

    const headers = [
      'Customer ID',
      'Full Name',
      'Email Address',
      'Phone Number',
      'Company / College',
      'Full Address',
      'City',
      'State',
      'PIN Code',
      'Registration Date',
      'Account Status',
      'Orders Count',
      'Total Spent (INR)',
    ];

    const rows = exportList.map((c) => [
      c.customerCode,
      c.fullName,
      c.email,
      c.mobile,
      c.companyOrCollege,
      c.fullAddress,
      c.city,
      c.state,
      c.pinCode,
      c.registrationDate.slice(0, 10),
      c.accountStatus,
      c.ordersCount,
      c.totalSpentInr,
    ]);

    const dateStamp = new Date().toISOString().slice(0, 10);

    if (format === 'xls' || format === 'excel' || format === 'xlsx') {
      const xml = toExcelSpreadsheetXml('Customers', headers, rows);
      res.setHeader('Content-Type', 'application/vnd.ms-excel; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="nexustekfusion-customers-${dateStamp}.xls"`
      );
      return res.send(xml);
    }

    const csv = `\uFEFF${toSafeCsv(headers, rows)}`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="nexustekfusion-customers-${dateStamp}.csv"`
    );
    res.send(csv);
  } catch (error) {
    console.error('Export customers error:', error);
    res.status(500).json({ error: 'Failed to export customer records.' });
  }
});

// 3. GET /api/admin/customers/:id/profile — Complete Customer Profile & Relational History
adminCustomersRouter.get('/:id/profile', async (req, res) => {
  try {
    await ensureCustomerManagementSchema();
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid customer ID.' });
    }

    const [custRow] = await db
      .select()
      .from(customers)
      .where(and(eq(customers.id, id), isNull(customers.deletedAt)))
      .limit(1);

    if (!custRow) {
      return res.status(404).json({ error: 'Customer record not found.' });
    }

    const emailLower = normalizeEmail(custRow.email);
    let linkedUser: typeof users.$inferSelect | undefined;
    if (custRow.userId) {
      const [u] = await db.select().from(users).where(eq(users.id, custRow.userId)).limit(1);
      linkedUser = u;
    }
    if (!linkedUser) {
      const [uByEmail] = await db
        .select()
        .from(users)
        .where(and(sql`lower(${users.email}) = ${emailLower}`, isNull(users.deletedAt)))
        .limit(1);
      linkedUser = uByEmail;
    }

    const uidForQuery = linkedUser?.id;

    const [
      addresses,
      custStoreOrders,
      custPrintOrders,
      custProjectEnquiries,
      custProjects,
      custProductEnquiries,
      custPcbEnquiries,
      custDroneRepairs,
      custPayments,
      custInvoices,
      custTickets,
      recentAudits,
    ] = await Promise.all([
      uidForQuery
        ? db
            .select()
            .from(customerAddresses)
            .where(eq(customerAddresses.userId, uidForQuery))
            .orderBy(desc(customerAddresses.isDefault), desc(customerAddresses.id))
        : Promise.resolve([]),
      uidForQuery
        ? db
            .select()
            .from(storeOrders)
            .where(and(eq(storeOrders.userId, uidForQuery), eq(storeOrders.isDeleted, false)))
            .orderBy(desc(storeOrders.createdAt))
        : Promise.resolve([]),
      uidForQuery
        ? db
            .select()
            .from(printingOrders)
            .where(eq(printingOrders.userId, uidForQuery))
            .orderBy(desc(printingOrders.createdAt))
        : Promise.resolve([]),
      db
        .select()
        .from(projectEnquiries)
        .where(
          and(
            eq(projectEnquiries.isDeleted, false),
            uidForQuery
              ? or(eq(projectEnquiries.userId, uidForQuery), sql`lower(${projectEnquiries.customerEmail}) = ${emailLower}`)
              : sql`lower(${projectEnquiries.customerEmail}) = ${emailLower}`
          )
        )
        .orderBy(desc(projectEnquiries.createdAt)),
      uidForQuery
        ? db
            .select()
            .from(projects)
            .where(and(eq(projects.userId, uidForQuery), eq(projects.isDeleted, false)))
            .orderBy(desc(projects.createdAt))
        : Promise.resolve([]),
      db
        .select()
        .from(productEnquiries)
        .where(
          uidForQuery
            ? or(eq(productEnquiries.userId, uidForQuery), sql`lower(${productEnquiries.email}) = ${emailLower}`)
            : sql`lower(${productEnquiries.email}) = ${emailLower}`
        )
        .orderBy(desc(productEnquiries.createdAt)),
      db
        .select()
        .from(pcbEnquiries)
        .where(
          uidForQuery
            ? or(eq(pcbEnquiries.userId, uidForQuery), sql`lower(${pcbEnquiries.email}) = ${emailLower}`)
            : sql`lower(${pcbEnquiries.email}) = ${emailLower}`
        )
        .orderBy(desc(pcbEnquiries.createdAt)),
      db
        .select()
        .from(droneRepairBookings)
        .where(
          uidForQuery
            ? or(eq(droneRepairBookings.userId, uidForQuery), sql`lower(${droneRepairBookings.email}) = ${emailLower}`)
            : sql`lower(${droneRepairBookings.email}) = ${emailLower}`
        )
        .orderBy(desc(droneRepairBookings.createdAt)),
      uidForQuery
        ? db.select().from(payments).where(eq(payments.userId, uidForQuery)).orderBy(desc(payments.createdAt))
        : Promise.resolve([]),
      uidForQuery
        ? db
            .select()
            .from(invoices)
            .where(and(eq(invoices.userId, uidForQuery), eq(invoices.isDeleted, false)))
            .orderBy(desc(invoices.issuedAt))
        : Promise.resolve([]),
      db
        .select()
        .from(supportTickets)
        .where(
          uidForQuery
            ? or(eq(supportTickets.userId, uidForQuery), sql`lower(${supportTickets.email}) = ${emailLower}`)
            : sql`lower(${supportTickets.email}) = ${emailLower}`
        )
        .orderBy(desc(supportTickets.createdAt)),
      db
        .select()
        .from(auditLogs)
        .where(
          or(
            and(
              or(eq(auditLogs.entityType, 'customer'), eq(auditLogs.entityType, 'user')),
              eq(auditLogs.entityId, String(custRow.id))
            ),
            eq(auditLogs.actorUid, custRow.customerId)
          )
        )
        .orderBy(desc(auditLogs.createdAt))
        .limit(40),
    ]);

    const defaultAddr = addresses[0];
    const addrLine = defaultAddr
      ? [defaultAddr.houseFlat, defaultAddr.streetArea, defaultAddr.landmark]
          .map((s) => String(s || '').trim())
          .filter(Boolean)
          .join(', ')
      : '';

    const totalSpentInr = custPayments
      .filter((p) => p.status === 'verified')
      .reduce((sum, p) => sum + (p.amountInr || 0), 0);

    const regIso = new Date(custRow.registrationDate || custRow.createdAt).toISOString();

    res.json({
      customer: {
        id: custRow.id,
        userId: uidForQuery ?? null,
        customerCode: custRow.customerId || formatCustomerCode(custRow.id),
        uid: custRow.customerId || formatCustomerCode(custRow.id),
        fullName: custRow.fullName || '',
        email: custRow.email,
        mobile: custRow.phoneNumber || linkedUser?.mobile || '',
        companyOrCollege: custRow.companyOrCollege || '',
        fullAddress: String(custRow.fullAddress || '').trim() || addrLine || '',
        city: String(custRow.city || '').trim() || defaultAddr?.city || '',
        state: String(custRow.state || '').trim() || defaultAddr?.state || '',
        pinCode: String(custRow.pinCode || '').trim() || defaultAddr?.pinCode || '',
        role: linkedUser?.role || 'customer',
        accountStatus: custRow.accountStatus || 'Active',
        statusReason: custRow.statusReason || '',
        emailVerified: Boolean(linkedUser?.emailVerified),
        phoneVerified: Boolean(linkedUser?.phoneVerified),
        isActive: custRow.accountStatus === 'Active',
        lastLoginAt: custRow.lastLoginAt ? new Date(custRow.lastLoginAt).toISOString() : null,
        registrationDate: regIso,
        createdAt: regIso,
        updatedAt: new Date(custRow.updatedAt).toISOString(),
        totalSpentInr,
        ordersCount: custStoreOrders.length + custPrintOrders.length,
        projectsCount: custProjectEnquiries.length,
        enquiriesCount: custProductEnquiries.length,
      },
      addresses,
      storeOrders: custStoreOrders,
      printingOrders: custPrintOrders,
      projectEnquiries: custProjectEnquiries,
      projects: custProjects,
      productEnquiries: custProductEnquiries,
      pcbEnquiries: custPcbEnquiries,
      droneRepairs: custDroneRepairs,
      payments: custPayments,
      invoices: custInvoices,
      supportTickets: custTickets,
      activityLogs: recentAudits,
    });
  } catch (error) {
    console.error('Get customer profile error:', error);
    res.status(500).json({ error: 'Failed to load complete customer profile.' });
  }
});

// 4. POST /api/admin/customers — Add New Customer directly in web_platform.customers
adminCustomersRouter.post('/', async (req: AuthRequest, res) => {
  try {
    await ensureCustomerManagementSchema();

    const cleanFullName = String(req.body.fullName || '').trim();
    const cleanEmail = normalizeEmail(req.body.email);
    const cleanMobile = normalizeMobile(req.body.mobile);
    const cleanCompany = String(req.body.companyOrCollege || '').trim();
    const cleanFullAddress = String(req.body.fullAddress || '').trim();
    const cleanCity = String(req.body.city || '').trim();
    const cleanState = String(req.body.state || '').trim();
    const cleanPinCode = String(req.body.pinCode || '').trim();
    const rawStatus = String(req.body.accountStatus || 'Active').trim();
    const accountStatus = VALID_ACCOUNT_STATUSES.has(rawStatus) ? rawStatus : 'Active';
    const providedPassword = String(req.body.password || '');

    if (!cleanFullName || cleanFullName.length < 2) {
      return res.status(400).json({ error: 'Full name is required (minimum 2 characters).' });
    }
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (cleanMobile && !/^\+?\d{10,15}$/.test(cleanMobile)) {
      return res.status(400).json({ error: 'Please enter a valid 10-15 digit phone number.' });
    }
    if (cleanPinCode && !/^[0-9]{4,10}$/.test(cleanPinCode)) {
      return res.status(400).json({ error: 'PIN Code must be 4 to 10 digits.' });
    }
    if (providedPassword && providedPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    // Check duplicate active email & mobile across customers and users
    const [existingCustEmail] = await db
      .select({ id: customers.id })
      .from(customers)
      .where(and(sql`lower(${customers.email}) = ${cleanEmail}`, isNull(customers.deletedAt)))
      .limit(1);
    const [existingUserEmail] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(sql`lower(${users.email}) = ${cleanEmail}`, isNull(users.deletedAt)))
      .limit(1);
    if (existingCustEmail || existingUserEmail) {
      return res.status(409).json({ error: 'A customer or account with this email already exists.' });
    }

    if (cleanMobile) {
      const [existingCustMobile] = await db
        .select({ id: customers.id })
        .from(customers)
        .where(and(eq(customers.phoneNumber, cleanMobile), isNull(customers.deletedAt)))
        .limit(1);
      const [existingUserMobile] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.mobile, cleanMobile), isNull(users.deletedAt)))
        .limit(1);
      if (existingCustMobile || existingUserMobile) {
        return res.status(409).json({ error: 'This phone number is already registered with another account.' });
      }
    }

    const rawPassword = providedPassword || `Ntf!${crypto.randomBytes(12).toString('base64url')}9A`;
    const hashed = hashPassword(rawPassword);
    const now = new Date();

    let createdCust: typeof customers.$inferSelect;
    try {
      const [inserted] = await db
        .insert(customers)
        .values({
          fullName: cleanFullName,
          email: cleanEmail,
          phoneNumber: cleanMobile,
          companyOrCollege: cleanCompany,
          fullAddress: cleanFullAddress,
          city: cleanCity,
          state: cleanState,
          pinCode: cleanPinCode,
          passwordHash: hashed,
          accountStatus,
          statusReason: accountStatus !== 'Active' ? 'Set during Admin customer creation' : '',
          registrationDate: now,
        })
        .returning();
      createdCust = inserted;
    } catch (dbErr: any) {
      const pgCode = dbErr?.code || dbErr?.cause?.code;
      if (pgCode === '23505') {
        return res.status(409).json({ error: 'Duplicate email or phone number detected.' });
      }
      throw dbErr;
    }

    let linkedUser: typeof users.$inferSelect;
    try {
      const [insertedUser] = await db
        .insert(users)
        .values({
          uid: createdCust.customerId,
          authUserId: null,
          email: cleanEmail,
          fullName: cleanFullName,
          mobile: cleanMobile,
          companyOrCollege: cleanCompany,
          fullAddress: cleanFullAddress,
          city: cleanCity,
          state: cleanState,
          pinCode: cleanPinCode,
          role: 'customer',
          passwordHash: hashed,
          emailVerified: false,
          phoneVerified: false,
          emailConfirmedAt: '',
          phoneConfirmedAt: '',
          accountStatus,
          statusReason: accountStatus !== 'Active' ? 'Set during Admin customer creation' : '',
          isActive: accountStatus === 'Active',
        })
        .returning();
      linkedUser = insertedUser;

      await db
        .update(customers)
        .set({ userId: linkedUser.id, updatedAt: now })
        .where(eq(customers.id, createdCust.id));
    } catch (linkErr) {
      await db.delete(customers).where(eq(customers.id, createdCust.id)).catch(() => {});
      throw linkErr;
    }

    await upsertDefaultCustomerAddress(linkedUser.id, {
      fullName: cleanFullName,
      mobile: cleanMobile,
      fullAddress: cleanFullAddress,
      city: cleanCity,
      state: cleanState,
      pinCode: cleanPinCode,
    });

    await logAudit({
      actorUid: req.dbUser!.uid,
      actorEmail: req.dbUser!.email,
      action: 'ADMIN_CREATE_CUSTOMER',
      entityType: 'customer',
      entityId: createdCust.id,
      details: {
        customerCode: createdCust.customerId,
        email: createdCust.email,
        accountStatus: createdCust.accountStatus,
      },
    });

    const { customers: list } = await buildEnrichedCustomers({ search: createdCust.customerId });
    const enriched = list.find((c) => c.id === createdCust.id);
    res.status(201).json({ customer: enriched || createdCust });
  } catch (error: any) {
    console.error('Create customer error:', error);
    res.status(500).json({ error: error?.message || 'Failed to add new customer.' });
  }
});

// 5. PATCH /api/admin/customers/:id — Edit Customer (Inline Row Edit or Full Edit Form)
adminCustomersRouter.patch('/:id', async (req: AuthRequest, res) => {
  try {
    await ensureCustomerManagementSchema();

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid customer ID.' });
    }

    const [existing] = await db
      .select()
      .from(customers)
      .where(and(eq(customers.id, id), isNull(customers.deletedAt)))
      .limit(1);

    if (!existing) {
      return res.status(404).json({ error: 'Customer record not found.' });
    }

    const cleanFullName =
      req.body.fullName !== undefined ? String(req.body.fullName || '').trim() : existing.fullName;
    const cleanEmail =
      req.body.email !== undefined ? normalizeEmail(req.body.email) : normalizeEmail(existing.email);
    const cleanMobile =
      req.body.mobile !== undefined ? normalizeMobile(req.body.mobile) : existing.phoneNumber;
    const cleanCompany =
      req.body.companyOrCollege !== undefined
        ? String(req.body.companyOrCollege || '').trim()
        : existing.companyOrCollege;
    const cleanFullAddress =
      req.body.fullAddress !== undefined
        ? String(req.body.fullAddress || '').trim()
        : existing.fullAddress;
    const cleanCity = req.body.city !== undefined ? String(req.body.city || '').trim() : existing.city;
    const cleanState = req.body.state !== undefined ? String(req.body.state || '').trim() : existing.state;
    const cleanPinCode =
      req.body.pinCode !== undefined ? String(req.body.pinCode || '').trim() : existing.pinCode;
    const requestedStatus =
      req.body.accountStatus !== undefined
        ? String(req.body.accountStatus || '').trim()
        : existing.accountStatus;
    const statusReason =
      req.body.statusReason !== undefined
        ? String(req.body.statusReason || '').trim()
        : existing.statusReason;
    const newPassword = req.body.password !== undefined ? String(req.body.password || '') : '';

    if (!cleanFullName || cleanFullName.length < 2) {
      return res.status(400).json({ error: 'Full name must be at least 2 characters.' });
    }
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (cleanMobile && !/^\+?\d{10,15}$/.test(cleanMobile)) {
      return res.status(400).json({ error: 'Please enter a valid 10-15 digit phone number.' });
    }
    if (cleanPinCode && !/^[0-9]{4,10}$/.test(cleanPinCode)) {
      return res.status(400).json({ error: 'PIN Code must be 4 to 10 digits.' });
    }
    if (!VALID_ACCOUNT_STATUSES.has(requestedStatus)) {
      return res.status(400).json({ error: 'Account Status must be Active, Suspended, or Deactivated.' });
    }
    if (newPassword && newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    // Duplicate email & mobile checks in web_platform.customers
    const [dupCustEmail] = await db
      .select({ id: customers.id })
      .from(customers)
      .where(and(ne(customers.id, id), sql`lower(${customers.email}) = ${cleanEmail}`, isNull(customers.deletedAt)))
      .limit(1);
    if (dupCustEmail) {
      return res.status(409).json({ error: 'Another active customer already uses this email address.' });
    }

    if (cleanMobile) {
      const [dupCustMobile] = await db
        .select({ id: customers.id })
        .from(customers)
        .where(and(ne(customers.id, id), eq(customers.phoneNumber, cleanMobile), isNull(customers.deletedAt)))
        .limit(1);
      if (dupCustMobile) {
        return res.status(409).json({ error: 'Another active customer already uses this phone number.' });
      }
    }

    const updatedPasswordHash = newPassword ? hashPassword(newPassword) : existing.passwordHash;
    const now = new Date();

    const [updatedCust] = await db
      .update(customers)
      .set({
        fullName: cleanFullName,
        email: cleanEmail,
        phoneNumber: cleanMobile,
        companyOrCollege: cleanCompany,
        fullAddress: cleanFullAddress,
        city: cleanCity,
        state: cleanState,
        pinCode: cleanPinCode,
        passwordHash: updatedPasswordHash,
        accountStatus: requestedStatus,
        statusReason: requestedStatus === 'Active' ? '' : statusReason,
        updatedAt: now,
      })
      .where(eq(customers.id, id))
      .returning();

    // Sync linked web_platform.users record if present
    let targetUserId = existing.userId;
    if (!targetUserId) {
      const [uByEmail] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(sql`lower(${users.email}) = ${normalizeEmail(existing.email)}`, isNull(users.deletedAt)))
        .limit(1);
      if (uByEmail) targetUserId = uByEmail.id;
    }

    if (targetUserId) {
      await db
        .update(users)
        .set({
          fullName: cleanFullName,
          email: cleanEmail,
          mobile: cleanMobile,
          companyOrCollege: cleanCompany,
          fullAddress: cleanFullAddress,
          city: cleanCity,
          state: cleanState,
          pinCode: cleanPinCode,
          ...(newPassword ? { passwordHash: updatedPasswordHash } : {}),
          accountStatus: requestedStatus,
          statusReason: requestedStatus === 'Active' ? '' : statusReason,
          isActive: requestedStatus === 'Active',
          updatedAt: now,
        })
        .where(eq(users.id, targetUserId));

      if (!existing.userId) {
        await db
          .update(customers)
          .set({ userId: targetUserId, updatedAt: now })
          .where(eq(customers.id, id));
      }

      if (
        req.body.fullAddress !== undefined ||
        req.body.city !== undefined ||
        req.body.state !== undefined ||
        req.body.pinCode !== undefined
      ) {
        await upsertDefaultCustomerAddress(targetUserId, {
          fullName: cleanFullName,
          mobile: cleanMobile,
          fullAddress: cleanFullAddress,
          city: cleanCity,
          state: cleanState,
          pinCode: cleanPinCode,
        });
      }

      if (requestedStatus !== 'Active') {
        await db.delete(adminSessions).where(eq(adminSessions.userId, targetUserId));
      }
    }

    await logAudit({
      actorUid: req.dbUser!.uid,
      actorEmail: req.dbUser!.email,
      action:
        requestedStatus !== existing.accountStatus
          ? `ADMIN_${requestedStatus.toUpperCase()}_CUSTOMER`
          : 'ADMIN_UPDATE_CUSTOMER',
      entityType: 'customer',
      entityId: id,
      details: {
        customerCode: updatedCust.customerId,
        email: updatedCust.email,
        accountStatus: updatedCust.accountStatus,
        city: updatedCust.city,
        state: updatedCust.state,
      },
    });

    const { customers: list } = await buildEnrichedCustomers({ search: updatedCust.customerId });
    const enriched = list.find((c) => c.id === id);
    res.json({ customer: enriched || updatedCust });
  } catch (error: any) {
    console.error('Update customer error:', error);
    const pgCode = error?.code || error?.cause?.code;
    if (pgCode === '23505') {
      return res.status(409).json({ error: 'Duplicate email or phone number detected.' });
    }
    res.status(500).json({ error: error?.message || 'Failed to update customer details.' });
  }
});

// 6. DELETE /api/admin/customers/:id — Soft-delete customer while preserving historical orders/invoices
adminCustomersRouter.delete('/:id', async (req: AuthRequest, res) => {
  try {
    await ensureCustomerManagementSchema();

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid customer ID.' });
    }

    const [existing] = await db
      .select()
      .from(customers)
      .where(and(eq(customers.id, id), isNull(customers.deletedAt)))
      .limit(1);

    if (!existing) {
      return res.status(404).json({ error: 'Customer not found or already deleted.' });
    }
    if (existing.userId && existing.userId === req.dbUser!.id) {
      return res.status(400).json({ error: 'You cannot delete your own active session account.' });
    }

    const reason =
      String(req.body?.reason || req.query.reason || '').trim() ||
      'Deleted from Customer Management Dashboard';
    const now = new Date();

    await db
      .update(customers)
      .set({
        deletedAt: now,
        accountStatus: 'Deactivated',
        statusReason: reason,
        updatedAt: now,
      })
      .where(eq(customers.id, id));

    if (existing.userId) {
      await db
        .update(users)
        .set({
          deletedAt: now,
          accountStatus: 'Deactivated',
          isActive: false,
          statusReason: reason,
          updatedAt: now,
        })
        .where(eq(users.id, existing.userId));

      await db.delete(adminSessions).where(eq(adminSessions.userId, existing.userId));
    }

    await logAudit({
      actorUid: req.dbUser!.uid,
      actorEmail: req.dbUser!.email,
      action: 'ADMIN_DELETE_CUSTOMER',
      entityType: 'customer',
      entityId: id,
      details: {
        customerCode: existing.customerId,
        email: existing.email,
        reason,
        preservedRelations: true,
      },
    });

    res.json({ ok: true, id, customerCode: existing.customerId });
  } catch (error: any) {
    console.error('Delete customer error:', error);
    res.status(500).json({ error: error?.message || 'Failed to delete customer record.' });
  }
});
