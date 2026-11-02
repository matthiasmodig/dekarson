/* Skapar lösenordshash för USERS i Cloudflare:  node worker/hash.js "ditt lösenord" */
const c=require("crypto"),pw=process.argv[2];
if(!pw){console.error('Användning: node worker/hash.js "lösenord"');process.exit(1);}
const salt=c.randomBytes(16).toString("hex"),it=100000;
console.log("pbkdf2$"+it+"$"+salt+"$"+c.pbkdf2Sync(pw,Buffer.from(salt,"hex"),it,32,"sha256").toString("hex"));
