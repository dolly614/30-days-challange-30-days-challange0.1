import { defineConfig } from "eslint/config";
import next from "eslint-config-next";

export default defineConfig([
  {
    extends: [...next],
    rules: {
      'no-restricted-imports': ['error', {
        paths: [{
          name: '@/lib/supabase-admin',
          message: 'supabase-admin can only be imported in server components or API routes.'
        }]
      }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
]);
