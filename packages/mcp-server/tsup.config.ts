import { defineConfig } from 'tsup';
import { readFileSync } from 'node:fs';

const packageVersion = (JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
) as { version: string }).version;

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  noExternal: [/.*/],
  platform: 'node',
  target: 'node18',
  define: {
    __PACKAGE_VERSION__: JSON.stringify(packageVersion),
  },
  banner: {
    js: '#!/usr/bin/env node',
  },
});
