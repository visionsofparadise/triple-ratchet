import js from "@eslint/js";
import barrelFiles from "eslint-plugin-barrel-files";
import checkFile from "eslint-plugin-check-file";
import importX from "eslint-plugin-import-x";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Global ignores
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/*.config.js",
      "**/*.config.ts",
      "**/*.test.ts",
      "**/__tests__/**",
    ],
  },

  // Base JS recommended
  js.configs.recommended,

  // TypeScript strict + stylistic
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  // TypeScript parser settings
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // Main rules for TypeScript files
  {
    files: ["**/*.ts"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.es2022,
      },
    },
    plugins: {
      "import-x": importX,
      "barrel-files": barrelFiles,
      "check-file": checkFile,
    },
    rules: {
      // === FUNCTIONS: Arrow functions by default ===
      "prefer-arrow-callback": "error",
      "arrow-body-style": ["error", "as-needed"],

      // === NAMING CONVENTIONS ===
      "@typescript-eslint/naming-convention": [
        "error",
        // Default: camelCase with leading underscore allowed
        {
          selector: "default",
          format: ["camelCase"],
          leadingUnderscore: "allow",
        },
        // Variables: camelCase, PascalCase (React components), UPPER_CASE (constants)
        {
          selector: "variable",
          format: ["camelCase", "PascalCase", "UPPER_CASE"],
          leadingUnderscore: "allow",
          custom: {
            regex: "^(_|[xyz]|.{2,})$",
            match: true,
          },
        },
        // Parameters: min 2 chars (except: x, y, z for coordinates)
        {
          selector: "parameter",
          format: ["camelCase", "PascalCase"],
          leadingUnderscore: "allowSingleOrDouble",
          filter: {
            regex: "^_+$",
            match: false,
          },
          custom: {
            regex: "^([xyz]|.{2,})$",
            match: true,
          },
        },
        // Functions: camelCase or PascalCase
        {
          selector: "function",
          format: ["camelCase", "PascalCase"],
        },
        // Type parameters (generics): single uppercase letter or PascalCase
        {
          selector: "typeParameter",
          format: ["PascalCase"],
          custom: { regex: "^[A-Z]([a-zA-Z0-9]*)?$", match: true },
        },
        // Interfaces: PascalCase
        {
          selector: "interface",
          format: ["PascalCase"],
        },
        // Type aliases: PascalCase
        {
          selector: "typeAlias",
          format: ["PascalCase"],
        },
        // Classes: PascalCase
        {
          selector: "class",
          format: ["PascalCase"],
        },
        // Enums and enum members: PascalCase or UPPER_CASE
        {
          selector: "enum",
          format: ["PascalCase"],
        },
        {
          selector: "enumMember",
          format: ["PascalCase", "UPPER_CASE"],
        },
        // Properties: camelCase (allow leading underscore for private)
        {
          selector: "property",
          format: ["camelCase", "PascalCase", "UPPER_CASE"],
          leadingUnderscore: "allow",
        },
        // Object literal properties: allow anything (API compatibility)
        {
          selector: "objectLiteralProperty",
          format: null,
        },
        // Type properties: allow anything (external API types)
        {
          selector: "typeProperty",
          format: null,
        },
        // Imports: allow any format (external packages)
        {
          selector: "import",
          format: null,
        },
      ],

      // === TYPESCRIPT: Interfaces over types ===
      "@typescript-eslint/consistent-type-definitions": ["error", "interface"],

      // === TYPESCRIPT: Array<T> over T[] ===
      "@typescript-eslint/array-type": ["error", { default: "generic" }],

      // === TYPESCRIPT: No explicit any, prefer unknown ===
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-return": "error",

      // === TYPESCRIPT: Prefer undefined over null ===
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/prefer-nullish-coalescing": "error",

      // === TYPESCRIPT: async/await over .then() ===
      "@typescript-eslint/promise-function-async": "off",
      "@typescript-eslint/no-floating-promises": ["error", { ignoreVoid: true }],
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/no-misused-promises": [
        "error",
        { checksVoidReturn: { attributes: false } },
      ],

      // === IMPORTS: Consistent type imports ===
      "@typescript-eslint/consistent-type-imports": [
        "error",
        {
          prefer: "type-imports",
          fixStyle: "inline-type-imports",
        },
      ],
      "@typescript-eslint/no-import-type-side-effects": "error",

      // === CODE QUALITY ===
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        { allowNumber: true, allowBoolean: true },
      ],
      "no-console": "off",
      "prefer-const": "error",
      "no-var": "error",
      eqeqeq: ["error", "always"],

      // === NAMING: No abbreviations ===
      "id-denylist": [
        "error",
        "btn",
        "cb",
        "ctx",
        "el",
        "elem",
        "err",
        "evt",
        "fn",
        "idx",
        "msg",
        "num",
        "obj",
        "opts",
        "params",
        "pkg",
        "ptr",
        "req",
        "res",
        "ret",
        "str",
        "temp",
        "tmp",
        "val",
        "var",
      ],

      // === IMPORTS: No extensions, no /index paths ===
      "import-x/extensions": [
        "error",
        "never",
        { ignorePackages: true },
      ],
      "import-x/no-useless-path-segments": [
        "error",
        { noUselessIndex: true },
      ],

      // === IMPORTS: No barrel files (except entry point) ===
      "barrel-files/avoid-barrel-files": "error",
      "barrel-files/avoid-re-export-all": "error",
      "barrel-files/avoid-namespace-import": "warn",

      // === RELAXATIONS ===
      "@typescript-eslint/no-unnecessary-type-parameters": "off",
      "@typescript-eslint/no-non-null-assertion": "warn",
      "@typescript-eslint/no-empty-function": [
        "error",
        { allow: ["arrowFunctions"] },
      ],
      "@typescript-eslint/unbound-method": "off",
      "@typescript-eslint/no-confusing-void-expression": [
        "error",
        { ignoreArrowShorthand: true },
      ],
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-namespace": "off",
      "@typescript-eslint/consistent-indexed-object-style": "off",
      "@typescript-eslint/no-unsafe-function-type": "off",
    },
  },

  // Library entry point is allowed to be a barrel file
  {
    files: ["src/index.ts"],
    rules: {
      "barrel-files/avoid-barrel-files": "off",
    },
  },

  // JavaScript files (config files)
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    ...tseslint.configs.disableTypeChecked,
    rules: {
      "prefer-arrow-callback": "error",
      "prefer-const": "error",
      "no-var": "error",
    },
  }
);
