# Update packages

Drop your update `.zip` files in this folder, then generate the manifest:

```bash
node scripts/make-manifest.js --version 10.2.21.0 --notes "What changed"
```

This creates `manifest.json` (sizes + SHA-256 hashes). The launcher:

1. calls `GET /api/updates/check?current=<installed>` (public),
2. asks the user to sign in (password or passkey),
3. downloads each package from `GET /api/updates/download/:file` (JWT required),
4. verifies SHA-256, closes `PandoraTool.exe`, extracts over the app folder,
   and relaunches it.

ZIP layout: paths inside the zip are relative to the app folder
(`targetDir` in the manifest, usually `.`), e.g. the zip should contain
`PandoraTool.exe`, `MetaCore.dll`, … at its root.

> `manifest.json` is git-ignored (it changes on every release).
> See `manifest.example.json` for the format.
