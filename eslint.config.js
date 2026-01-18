import tseslint from "typescript-eslint";
import baseConfig from "../../eslint.config.js";

/**
 * @xkore/triple-ratchet ESLint configuration.
 * Extends the base config from Projects/Code with project-specific overrides.
 */
export default tseslint.config(
  ...baseConfig,

  // Ignore test files
  {
    ignores: ["**/*.test.ts", "**/__tests__/**"],
  },

  // Project-specific TypeScript parser settings
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // Disable React rules (pure crypto library, no React)
  {
    files: ["**/*.ts"],
    rules: {
      // No React in this project
      "react/jsx-no-target-blank": "off",
      "react/jsx-curly-brace-presence": "off",

      // Allow console.log during development
      "no-console": "off",
    },
  },

  // Library entry point is allowed to be a barrel file
  {
    files: ["src/index.ts"],
    rules: {
      "barrel-files/avoid-barrel-files": "off",
    },
  }
);
