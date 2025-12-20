// Fetch index.html from the local server and save it as smoke_index.html
const fs = require('fs');

const URL = process.env.URL || 'http://127.0.0.1:8000/index.html';
const OUT = process.env.OUT || 'smoke_index.html';

async function waitForServer(url, attempts = 10, delayMs = 500) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { method: 'GET' });
      if (res.ok) return res;
    } catch (e) {
      // ignore
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  throw new Error('Server did not respond within timeout');
}

(async () => {
  try {
    const res = await waitForServer(URL, 20, 300);
    const text = await res.text();
    fs.writeFileSync(OUT, text, 'utf8');
    console.log('Saved', OUT);
  } catch (e) {
    console.error('Failed to fetch and save:', e.message);
    process.exit(2);
  }
})();
