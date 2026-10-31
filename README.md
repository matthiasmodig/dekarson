# Dekarsön energicentral

- `index.html`: själva sidan (en enda fil, inga beroenden). Publiceras via GitHub Pages på dekarson.matthiasmodig.se.
- `worker/`: Cloudflare Worker som sköter inloggning mot Homey (Athom OAuth) och proxar anrop. Nycklar ligger som Cloudflare-hemligheter, aldrig i repot.
