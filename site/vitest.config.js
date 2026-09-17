import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "happy-dom",
    environmentOptions: {
      happyDOM: {
        // Tests never load third-party scripts or stylesheets.
        settings: { disableJavaScriptFileLoading: true, disableCSSFileLoading: true },
      },
    },
    include: ["test/**/*.test.js"],
  },
});
