import type { Check } from "../types.js";

// Temporary check so the scan pipeline has something to run.
// Replace it with real checks once they exist.
export const placeholderCheck: Check = {
  id: "placeholder",
  name: "Placeholder check",
  severity: "info",
  async run(_projectPath) {
    return [];
  },
};
