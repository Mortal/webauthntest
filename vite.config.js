import { defineConfig } from 'vite';
import fs from 'fs';

// https://vitejs.dev/config/
export default defineConfig({
  server: {
    https: {
      key: fs.readFileSync('./key.pem'),
      cert: fs.readFileSync('./cert.pem'),
    },
    proxy: {
      '/rp': {
        target: 'https://localhost:4433',
        changeOrigin: true,
        secure: false,
      }
    }
  },
});
