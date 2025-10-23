import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  integrations: [tailwind()],
  // Produce a static site in `dist` so Express can serve it
  output: 'static',
  redirects: {
    '/': '/home'
  },
  server: {
    port: 4321,
    host: true
  }
});