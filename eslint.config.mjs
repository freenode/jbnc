import js from "@eslint/js";

export default [
  {
    files: ["**/*.js"],

    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",

      globals: {
        require: "readonly",
        module: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        process: "readonly",
        console: "readonly",
      },
    },

    rules: {
      // Bonnes pratiques
      "no-undef": "error",
      "no-var": "error",

      // Style
      /*"quotes": ["error", "single"],
      "indent": ["error", "tab"],
      "curly": ["error", "all"],*/
    },
  },

  js.configs.recommended,
];
