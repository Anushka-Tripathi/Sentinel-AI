const SUSPICIOUS_MARKERS = [
  "../",
  "..\\",
  "<script",
  "union select",
  "' or '1'='1",
  "\" or \"1\"=\"1",
  "${",
  "{{",
  "wget ",
  "curl ",
  "/etc/passwd",
  "powershell",
  "cmd.exe",
  "--",
  ";--"
];

function shannonEntropy(value) {
  if (!value) return 0;

  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return Number(entropy.toFixed(3));
}

function safeJsonParse(rawBody) {
  if (!rawBody) return null;
  try {
    return JSON.parse(rawBody);
  } catch {
    return null;
  }
}

function countSuspiciousMarkers(value) {
  const normalized = value.toLowerCase();
  return SUSPICIOUS_MARKERS.filter((marker) => normalized.includes(marker)).length;
}

function extractFeatures(req, rawBody) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const parsedBody = safeJsonParse(rawBody);
  const combinedText = `${url.pathname} ${url.search} ${rawBody || ""}`;
  const depth = url.pathname.split("/").filter(Boolean).length;

  return {
    method: req.method || "GET",
    path: url.pathname,
    query: url.search,
    statusCode: 200,
    userAgent: req.headers["user-agent"] || "unknown",
    role: req.headers["x-demo-role"] || "guest",
    contentType: req.headers["content-type"] || "none",
    payloadSize: Buffer.byteLength(rawBody || "", "utf8"),
    payloadEntropy: shannonEntropy(rawBody || ""),
    pathDepth: depth,
    suspiciousMarkerCount: countSuspiciousMarkers(combinedText),
    jsonBodyKeys: parsedBody && typeof parsedBody === "object" ? Object.keys(parsedBody).length : 0,
    timestamp: Date.now()
  };
}

module.exports = { extractFeatures };
