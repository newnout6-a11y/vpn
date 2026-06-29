const fs = require('fs');
const dbPath = 'C:/Users/Redmi/AppData/Local/Happ/subs.db';

if (!fs.existsSync(dbPath)) {
  console.log("subs.db not found");
  process.exit(1);
}

const dbBuffer = fs.readFileSync(dbPath);
const dbStr = dbBuffer.toString('utf8');

const regex = /vless:\/\/[^\s"'<]+/gi;
const matches = dbStr.match(regex);

if (matches) {
  const ipMatches = matches.filter(m => m.includes('144.31.1.75'));
  if (ipMatches.length > 0) {
    console.log("Found vless links for 144.31.1.75:");
    ipMatches.forEach(m => console.log(m));
  } else {
    console.log("Found vless links, but none for 144.31.1.75");
  }
} else {
  console.log("No vless links found in subs.db text dump.");
}
