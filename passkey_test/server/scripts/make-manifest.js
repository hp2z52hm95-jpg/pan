#!/usr/bin/env node
/**
 * Build packages/manifest.json from the files in packages/
 *
 * Usage:
 *   node scripts/make-manifest.js --version 10.2.21.0 --notes "Bug fixes"
 *   node scripts/make-manifest.js --app PandoraTool --version 10.2.21.0 --kind zip
 *
 * Every .zip/.exe/.dll in packages/ becomes one manifest entry with
 * size + sha256 (the launcher verifies the hash after download).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PACKAGES_DIR = path.join(__dirname, '..', 'packages');

function arg(name, def = '') {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

function sha256Of(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function main() {
  const app = arg('app', 'PandoraTool');
  const version = arg('version');
  const notes = arg('notes', '');
  const kind = arg('kind', 'zip');

  if (!version) {
    console.error('Missing required --version, e.g.: node scripts/make-manifest.js --version 10.2.21.0');
    process.exit(1);
  }

  fs.mkdirSync(PACKAGES_DIR, { recursive: true });

  const files = fs.readdirSync(PACKAGES_DIR).filter((f) => {
    if (f === 'manifest.json' || f.endsWith('.example.json') || f.endsWith('.md')) return false;
    return /\.(zip|exe|dll|bin)$/i.test(f);
  });

  if (files.length === 0) {
    console.error(`No package files found in ${PACKAGES_DIR} — copy your .zip update there first.`);
    process.exit(1);
  }

  const manifest = {
    app,
    channel: 'stable',
    latest: version,
    publishedAt: new Date().toISOString(),
    notes,
    packages: files.map((file) => {
      const full = path.join(PACKAGES_DIR, file);
      const stat = fs.statSync(full);
      return {
        file,
        version,
        kind: file.toLowerCase().endsWith('.zip') ? 'zip' : kind,
        targetDir: '.',
        size: stat.size,
        sha256: sha256Of(full)
      };
    })
  };

  fs.writeFileSync(
    path.join(PACKAGES_DIR, 'manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n'
  );

  console.log(`✓ manifest.json written: ${app} ${version} (${files.length} package(s))`);
  files.forEach((f) => console.log(`  - ${f}`));
}

main();
