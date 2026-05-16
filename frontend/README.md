# REDCON Platform Frontend (Next.js)

This is the **new React/Next.js frontend (Option A)** that consumes the existing Flask backend APIs under `/api/...`.

## Requirements

- Node.js **20+**
- npm **10+**

## Local Development (safe; does not change production)

1. Start the Flask backend (existing app) on `http://localhost:5000`.
2. In a new terminal:

```bash
cd /Users/n3dx0o/Downloads/AI/dashboard/frontend
npm install
export BACKEND_URL=http://localhost:5000
export NEXT_PUBLIC_BACKEND_ORIGIN=http://localhost:5000
npm run dev
```

Then open `http://localhost:3000`.

Notes:
- The Next app uses `next.config.js` rewrites so `/api/...` automatically proxies to `BACKEND_URL`.
- Login uses `/api/auth/login` and relies on the Flask **session cookie**.

## Safe Production Deployment Strategy

Recommended approach:
- Keep the existing Flask UI working as-is.
- Deploy Next.js under a new path like **`/app`** behind Nginx.
- Route `/api/*` to Flask (existing), and `/app/*` to Next.js.

Example Nginx idea (high level):
- `location /api/ { proxy_pass http://flask_upstream; }`
- `location /app/ { proxy_pass http://next_upstream; }`

This keeps cookies same-site and avoids CORS complexity.

### Production env vars (Next.js)

- `NEXT_BASE_PATH=/app`
- `NEXT_PUBLIC_BACKEND_ORIGIN=` (empty string) because it’s same-origin behind Nginx

### Local dev env vars (Next.js)

- `BACKEND_URL=http://localhost:5000`
- `NEXT_PUBLIC_BACKEND_ORIGIN=http://localhost:5000` (so the temporary redirect pages can open the legacy Flask detail screens)
- `NEXT_BASE_PATH=` (empty for local dev)



