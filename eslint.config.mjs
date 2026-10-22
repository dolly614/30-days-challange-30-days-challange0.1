import nextPlugin from "@next/eslint-plugin-next";

export default [
  {
    ignores: ['.next/**', '.next-dev/**', 'node_modules/**', 'scripts/**'],
  },
  {
    plugins: {
      "@next/next": nextPlugin,
    },
    rules: {
      ...nextPlugin.configs.recommended.rules,
      ...nextPlugin.configs["core-web-vitals"].rules,
      'no-restricted-imports': ['error', {
        paths: [{
          name: '@/lib/supabase-admin',
          message: 'supabase-admin can only be imported in server components or API routes.'
        }]
      }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
];
