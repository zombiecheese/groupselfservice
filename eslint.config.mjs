// ESLint v9 flat config for the Node TypeScript portion of the project.
// Browser-side scripts under public/ and EJS templates under views/ are
// intentionally excluded — they use their own global set and are short
// enough to review by hand. Prettier owns formatting (see .prettierrc.json).

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      "data/**",
      "public/**",
      "views/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
  {
    languageOptions: {
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
      globals: {
        process: "readonly",
        Buffer: "readonly",
        console: "readonly",
        fetch: "readonly",
        AbortSignal: "readonly",
        AbortController: "readonly",
        Response: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        crypto: "readonly",
        NodeJS: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      // Module augmentation in auth-middleware uses an Express namespace
      // declaration; required by @types/express, so allow it.
      "@typescript-eslint/no-namespace": "off",
      // LDAP filter escapes legitimately include \x00; the addr fallback
      // in the LDAP repo rebinds the variable for clarity.
      "no-control-regex": "off",
      "no-useless-assignment": "off",
      "no-console": ["warn", { allow: ["warn", "error"] }],
      eqeqeq: ["error", "smart"],
    },
  },
  {
    files: ["tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
    },
  }
);
