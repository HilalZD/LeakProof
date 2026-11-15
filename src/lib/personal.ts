// Which column, field and table names hold personal data. Shared by the
// Supabase RLS check and the API-auth check.

const PERSONAL_COLUMN = [
  /e_?mail/,
  /phone|mobile|whatsapp/,
  /address|street|city|postcode|postal|zip_?code/,
  /^(?:first_?name|last_?name|full_?name|display_?name|user_?name|real_?name|surname)$/,
  /(?:^|_)(?:customer|patient|client|member|contact|guest|owner|user|sender|recipient)_?name$/,
  /birth|^dob$/,
  /ssn|passport|national_?id|tax_?id/,
  /^(?:user|owner|author|inviter|invitee|customer|patient|member|profile|client|sender|recipient)_?id$/,
  /^ip$|ip_?address/,
];

// Tables (and Prisma models) that hold people.
const PERSONAL_TABLE =
  /^(?:profiles?|users?|user_\w+|accounts?|customers?|clients?|members?|patients?|contacts?|subscribers?|leads?|invites?|invitations?|bookings?|orders?|messages?)$/;

/** customerName → customer_name, "Email" → email. */
export const toSnake = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();

export function isPersonalTable(name: string): boolean {
  return PERSONAL_TABLE.test(toSnake(name.replace(/^.*\./, "").replace(/"/g, "")));
}

/**
 * Whether a column holds personal data. A bare "name" only counts on a table
 * that holds people (or an unknown table): products.name is a product name.
 */
export function isPersonalColumn(column: string, table?: string): boolean {
  const c = toSnake(column);
  if (c === "name") return table === undefined || isPersonalTable(table);
  return PERSONAL_COLUMN.some((p) => p.test(c));
}
