# Dradis Issue Map

A local Node.js app that fetches data from your Dradis instance and plots
issues on a North America map, colored by tag.

## Security design

- **API token never touches the browser** — stored in `.env`, used server-side only
- **No CORS issues** — the browser talks only to `localhost`; the server talks to Dradis
- **TLS handled properly** — use `CA_CERT_PATH` for self-signed certs instead of disabling validation
- **Bound to 127.0.0.1 only** — the server is not accessible from other machines on the network
- **Content-Security-Policy** header on the frontend blocks unexpected external connections

## Requirements

- Node.js 18 or later
- Access to a Dradis instance with the REST API enabled

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Copy the example env file and fill in your values:
   ```bash
   cp .env.example .env
   ```

   Edit `.env`:
   ```
   DRADIS_HOST=https://192.168.68.73
   DRADIS_TOKEN=your_api_token_here
   ```

3. (Optional) If your Dradis uses a self-signed certificate, export it and add:
   ```
   CA_CERT_PATH=/path/to/dradis-ca.pem
   ```
   This is safer than disabling TLS validation entirely.

   **How to export the cert from your browser:**
   - Chrome/Edge: click the padlock → Certificate → Details → Export
   - Firefox: click the padlock → More Information → View Certificate → Export

4. Start the server:
   ```bash
   npm start
   ```

5. Open your browser to `http://localhost:3000`

## How it works

- Projects are fetched from `/pro/api/projects`
- For each project, the `dradis.coordinates` document property is read
  (expected format: `lat,lon` e.g. `40.71,-74.01`)
- Issues are fetched from `/pro/api/projects/:id/issues`
- Only projects that have a `dradis.coordinates` property appear on the map
- Markers are colored by the issue's first tag

## Setting coordinates on a project

In Dradis, add a Document Property to your project:
- Key: `dradis.coordinates`
- Value: `latitude,longitude` (e.g. `40.7128,-74.0060` for New York)


# License
GPL-2.0 — See [LICENSE](https://github.com/dradis/dradis-map/blob/main/LICENSE.txt) for details.
