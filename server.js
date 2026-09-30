// Minimal authenticated forward proxy (HTTP + CONNECT), allowlisted to oddsportal.com.
// Deploy on Render Singapore so browsing oddsportal.com exits via a Singapore IP,
// which shows the most bookmakers (vs US IP which shows very few).
const http = require("http");
const net = require("net");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "10000", 10);
const PROXY_USER = process.env.PROXY_USER || "";
const PROXY_PASS = process.env.PROXY_PASS || "";

function allowedHost(hostname) {
  const h = String(hostname || "").toLowerCase().split(":")[0].trim();
  return h === "oddsportal.com" || h.endsWith(".oddsportal.com");
}

function checkAuth(req) {
  if (!PROXY_USER || !PROXY_PASS) return false;
  const hdr = req.headers["proxy-authorization"] || "";
  const m = /^basic\s+(.+)$/i.exec(hdr.trim());
  if (!m) return false;
  let decoded;
  try {
    decoded = Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return false;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  const u = Buffer.from(decoded.slice(0, idx));
  const p = Buffer.from(decoded.slice(idx + 1));
  const eu = Buffer.from(PROXY_USER);
  const ep = Buffer.from(PROXY_PASS);
  return (
    u.length === eu.length &&
    crypto.timingSafeEqual(u, eu) &&
    p.length === ep.length &&
    crypto.timingSafeEqual(p, ep)
  );
}

function needAuth(res) {
  res.writeHead(407, {
    "Proxy-Authenticate": 'Basic realm="oddsportal-proxy"',
    "Content-Type": "text/plain",
  });
  res.end("Proxy authentication required");
}

function forbidden(res, msg) {
  res.writeHead(403, { "Content-Type": "text/plain" });
  res.end(msg || "Host not allowed through this proxy");
}

const server = http.createServer((req, res) => {
  // Render health check + liveness (no auth)
  if (req.url === "/health" || req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }
  if (!checkAuth(req)) return needAuth(res);

  // Expect absolute-form URL for proxy requests
  let target;
  try {
    target = new URL(req.url);
  } catch {
    return forbidden(res, "Absolute URL required");
  }
  if (!allowedHost(target.hostname)) return forbidden(res);
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return forbidden(res, "Only http/https allowed");
  }

  const headers = { ...req.headers };
  delete headers["proxy-authorization"];
  headers.host = target.host;

  const proxyReq = http.request(
    {
      host: target.hostname,
      port: target.port || 80,
      method: req.method,
      path: target.pathname + target.search,
      headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
    res.end("Bad gateway");
  });
  req.pipe(proxyReq);
});

server.on("connect", (req, clientSocket, head) => {
  // req.url is "host:port"
  const [hostname, portStr] = String(req.url || "").split(":");
  const port = parseInt(portStr || "443", 10);
  if (!checkAuth(req)) {
    clientSocket.write(
      'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="oddsportal-proxy"\r\n\r\n'
    );
    clientSocket.destroy();
    return;
  }
  if (!allowedHost(hostname) || !(port === 80 || port === 443)) {
    clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    clientSocket.destroy();
    return;
  }
  const srvSocket = net.connect(port, hostname, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) srvSocket.write(head);
    srvSocket.pipe(clientSocket);
    clientSocket.pipe(srvSocket);
  });
  const onErr = () => {
    clientSocket.destroy();
    srvSocket.destroy();
  };
  srvSocket.on("error", onErr);
  clientSocket.on("error", onErr);
});

server.listen(PORT, () => {
  console.log(`oddsportal-proxy listening on ${PORT}`);
});
