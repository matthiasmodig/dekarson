# Dekarsön energicentral

- `index.html`: själva sidan (en enda fil, inga beroenden). Publiceras via GitHub Pages på dekarson.matthiasmodig.se.
- `worker/`: Cloudflare Worker som sköter inloggning mot Homey (Athom OAuth) och proxar anrop. Nycklar ligger som Cloudflare-hemligheter, aldrig i repot.

## Inloggning med användarnamn och lösenord (två användare)

Sidan visar en inloggningsruta innan något annat. Lösenorden ligger som hashar i Cloudflare, aldrig i sidan.

1. Skapa en hash per användare: `node worker/hash.js "lösenordet"`
2. I Cloudflare, workern `dekarson-api`, Settings, Variables and Secrets: lägg till en **secret** med namnet `USERS` och värdet
   `{"matthias":"pbkdf2$100000$...","anna":"pbkdf2$100000$..."}` (användarnamn med små bokstäver).
3. Driftsätt den nya `worker/worker.js`.

Max 8 felförsök per IP och 15 minuter. Sessionen gäller i 30 dagar. Homey-kopplingen (Admin, Logga in med Homey) behövs fortfarande en gång.
