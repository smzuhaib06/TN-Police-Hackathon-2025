// Minimal static file server with no external dependencies
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000; // Use port 3000 by default
const ROOT = process.cwd();

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.ico': 'image/x-icon'
};

function send404(res) {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('404 Not Found');
}

const server = http.createServer((req, res) => {
  try {
    const safePath = path.normalize(decodeURIComponent(req.url.split('?')[0] || '/'));
    let filePath = path.join(ROOT, safePath);

    // If the path is a directory, serve index.html
    if (filePath.endsWith(path.sep)) filePath = path.join(filePath, 'index.html');

    // If url is '/', serve index.html
    if (safePath === '/' || safePath === '') {
      filePath = path.join(ROOT, 'index.html');
    }

    // Prevent path escaping the root
    if (!filePath.startsWith(ROOT)) {
      send404(res);
      return;
    }

    fs.stat(filePath, (err, stats) => {
      if (err || !stats.isFile()) {
        // fallback: try index.html for directories
        if (err && err.code === 'ENOENT') {
          send404(res);
          return;
        }
        send404(res);
        return;
      }

      const ext = path.extname(filePath).toLowerCase();
      const type = mime[ext] || 'application/octet-stream';
      res.setHeader('Content-Type', type);
      res.setHeader('Cache-Control', 'no-cache');
      const stream = fs.createReadStream(filePath);
      stream.pipe(res);
      stream.on('error', () => send404(res));
    });
  } catch (e) {
    send404(res);
  }
});

server.listen(PORT, (err) => {
  if (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
  const actualPort = server.address().port;
  console.log(`Static server running at http://127.0.0.1:${actualPort}`);
  console.log(`Serving files from ${ROOT}`);
  // Write port to a file so frontend can read it
  fs.writeFileSync(path.join(ROOT, '.frontend-port'), String(actualPort));
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use`);
  } else {
    console.error('Server error:', err.message);
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
