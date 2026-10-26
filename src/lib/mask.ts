/**
 * Never show a full secret. Long values keep their first 8 and last 4
 * characters; short ones reveal little or nothing, since a few characters of
 * a short password are most of it.
 */
export function mask(value: string): string {
  if (value.length < 12) return "****";
  if (value.length <= 16) return value.slice(0, 4) + "****";
  return value.slice(0, 8) + "****" + value.slice(-4);
}
