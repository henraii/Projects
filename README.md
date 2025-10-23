yo2 Esen jagi, Erkhes(James Harden) 2 bn

## Deployment (Render)

These instructions show how to deploy the project as a single Node service on Render. The repository is configured to build a static Astro site (`dist`) then run `server.js` to serve the frontend and API from the same origin.

1. Connect your Git repo to Render and create a new **Web Service**.
	- Environment: Node
	- Branch: main (or whichever branch you want to deploy)
	- Build Command: npm ci && npm run build
	- Start Command: npm run start

2. Add environment variables (Render -> Service -> Environment):
	- MONGODB_URI (your MongoDB connection string)
	- JWT_SECRET (your JWT secret)
	- FRONTEND_URL (optional; used for CORS if you restrict origins)

3. Deploy. After build completes, your site will be available at the Render URL. API endpoints are available under the same domain (e.g. `https://<service>.onrender.com/api/health`).

Notes:
- The app serves static files from `dist` (output of `astro build`) via Express. The server listens on the PORT Render provides (process.env.PORT).
- Render's filesystem is ephemeral. Uploaded files in `uploads/` will not persist across restarts. For persistent uploads, use S3, DigitalOcean Spaces, Cloudinary, etc., and store URLs in MongoDB.

## Local testing

1. Install and build:

```powershell
npm ci
npm run build
```

2. Run the server locally (PowerShell):

```powershell
$env:PORT=3001; npm start
# Open http://localhost:3001 and check http://localhost:3001/api/health
```

3. During development you can run frontend and backend concurrently:

```powershell
npm run dev
```

## Troubleshooting

- If Render reports "no endpoint is given" or the service doesn't appear healthy, ensure the service start command runs a process that listens on the PORT Render assigns (Render sets `PORT` in environment). `server.js` uses `process.env.PORT` so that should be OK.
- Ensure environment variables (especially `MONGODB_URI`) are set in the Render dashboard; otherwise the server will fail trying to connect to the database and may exit.

## Next improvements

- Move file uploads to a persistent storage provider.
- Use Render's secrets to manage production credentials instead of committing them to YAML or code.
- Optionally convert to the Astro `adapter-node` if you prefer Astro to serve the server bundle directly (not necessary with current Express approach).

