/**
 * Update Distribution Routes - Package updater backend
 *
 * Flow:
 *  1. Launcher calls GET /api/updates/check (public) to see if a new version exists
 *  2. User signs in (password or passkey) to get a JWT
 *  3. Launcher downloads packages from GET /api/updates/download/:file (JWT required)
 *  4. Launcher verifies SHA-256, closes PandoraTool.exe, replaces files, relaunches
 *
 * Packages live in <server>/packages/ next to a manifest.json created with:
 *   node scripts/make-manifest.js --version 10.2.21.0 --notes "..."
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const { authenticateToken } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');

const PACKAGES_DIR = process.env.PACKAGES_DIR
  || path.join(__dirname, '..', '..', 'packages');

function readManifest() {
  try {
    const p = path.join(PACKAGES_DIR, 'manifest.json');
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

// Numeric dotted-version compare: -1 if a<b, 0 if equal, 1 if a>b
function cmpVersions(a, b) {
  const pa = String(a || '').split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b || '').split('.').map((x) => parseInt(x, 10) || 0);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/**
 * GET /api/updates/check?app=PandoraTool&current=10.2.20.0
 * Public — the launcher calls this before login to show "update available".
 */
router.get('/check', (req, res, next) => {
  try {
    const { app = 'PandoraTool', current = '0.0.0.0' } = req.query;
    const manifest = readManifest();

    if (!manifest || manifest.app !== app) {
      return res.json({ updateAvailable: false, current, latest: current, packages: [] });
    }

    const available = cmpVersions(current, manifest.latest) < 0;

    res.json({
      updateAvailable: available,
      current,
      latest: manifest.latest,
      notes: manifest.notes || '',
      publishedAt: manifest.publishedAt || null,
      packages: available ? manifest.packages : []
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/updates/download/:file
 * Auth required — only signed-in users (password OR passkey session) can
 * download update packages. Every download is audit-logged.
 */
router.get('/download/:file', authenticateToken, async (req, res, next) => {
  try {
    const name = req.params.file;

    // Strict file name check (no paths, no traversal)
    if (!/^[\w][\w.\- ]*$/.test(name) || name.includes('..')) {
      return res.status(400).json({ error: 'Invalid file name' });
    }

    const manifest = readManifest();
    const entry = manifest && manifest.packages.find((p) => p.file === name);

    if (!entry) {
      return res.status(404).json({ error: 'Package not found in manifest' });
    }

    const filePath = path.join(PACKAGES_DIR, name);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Package file missing on server' });
    }

    await logAudit(req.user.id, 'update_downloaded', {
      file: name,
      version: entry.version,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(entry.size));
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    fs.createReadStream(filePath).pipe(res);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
