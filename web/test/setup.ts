import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  document.cookie = "aigk_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
});
