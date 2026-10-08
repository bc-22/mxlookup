# MX Bulk Checker

Paste or upload up to 1,000 domains and check their MX records. Runs entirely on Vercel (static page + one serverless function).

## Deploy
1. Push this folder to a GitHub repo.
2. In Vercel: **Add New → Project → Import** the repo.
3. Framework Preset: **Other**. Leave build/output settings empty. Deploy.

## How it works
- `public/index.html` parses and de-duplicates the list, then splits it into batches of 25.
- Up to 4 batches run in parallel against `api/mx.js`, which resolves MX records with Node's DNS resolver.
- Results can be filtered and exported as CSV.

## Tuning
- Batch size / parallelism: `BATCH` and `PARALLEL` in `public/index.html`.
- Server cap per request: `MAX_PER_REQUEST` in `api/mx.js` (keep it within the function time limit).
- Raise the 1,000 cap with `LIMIT` in `public/index.html`.

## Protect it
The endpoint is public. To stop others using your quota, add Vercel Password Protection / Deployment Protection, or put an API key check in `api/mx.js`.
