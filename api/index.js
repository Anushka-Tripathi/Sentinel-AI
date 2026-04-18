const http = require("http");
const fs = require("fs");
const path = require("path");
const { extractFeatures } = require("../src/engine/featureExtractor");
const { ThreatDetectionEngine } = require("../src/engine/riskScorer");
const { runScenario } = require("../simulator/scenarioRunner");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "..", "public");
const engine = new ThreatDetectionEngine();
const simulationState = {
  running: false,
  mode: null,
  lastStatus: "idle",
  message: "No simulation started yet",
  updatedAt: new Date().toISOString()
};

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify(payload));
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const relativePath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const safePath = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: "Forbidden" });
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      "Content-Type": CONTENT_TYPES[ext] || "application/octet-stream",
      "Cache-Control": "no-store"
    });
    res.end(content);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let rawBody = "";
    req.on("data", (chunk) => {
      rawBody += chunk;
      if (rawBody.length > 1_000_000) {
        req.destroy();
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => resolve(rawBody));
    req.on("error", reject);
  });
}

function resolveSessionId(req) {
  return (
    req.headers["x-session-id"] ||
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "anonymous-session"
  );
}

function updateSimulationState(patch) {
  Object.assign(simulationState, patch, {
    updatedAt: new Date().toISOString()
  });
}

function triggerSimulation(mode) {
  if (simulationState.running) {
    return {
      accepted: false,
      state: simulationState,
      message: `A ${simulationState.mode} simulation is already running`
    };
  }

  updateSimulationState({
    running: true,
    mode,
    lastStatus: "running",
    message: `${mode} simulation started`
  });

  runScenario(mode, {
    host: "localhost",
    port: PORT,
    onEvent: ({ route, result }) => {
      updateSimulationState({
        running: true,
        mode,
        lastStatus: "running",
        message: `${mode} simulation: ${route} -> ${result.status} ${result.body.riskLevel || "NA"}`
      });
    }
  })
    .then(() => {
      updateSimulationState({
        running: false,
        mode,
        lastStatus: "completed",
        message: `${mode} simulation completed`
      });
    })
    .catch((error) => {
      updateSimulationState({
        running: false,
        mode,
        lastStatus: "failed",
        message: `${mode} simulation failed: ${error.message}`
      });
    });

  return {
    accepted: true,
    state: simulationState,
    message: `${mode} simulation launched`
  };
}

function resetSimulationState() {
  updateSimulationState({
    running: false,
    mode: null,
    lastStatus: "idle",
    message: "Engine reset complete. Start a fresh normal simulation."
  });
}

function handleDemoEndpoint(req, res, event) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (event.level === "HIGH") {
    sendJson(res, 403, {
      decision: "blocked",
      riskLevel: event.level,
      riskScore: event.score,
      reasons: event.reasons,
      path: url.pathname
    });
    return;
  }

  const responses = {
    "/demo/login": {
      decision: "allowed",
      message: "Login flow accepted",
      next: ["/demo/products", "/demo/profile"]
    },
    "/demo/products": {
      decision: "allowed",
      items: ["Laptop", "Security Camera", "Router"],
      next: ["/demo/cart", "/demo/profile"]
    },
    "/demo/cart": {
      decision: "allowed",
      status: "Cart updated"
    },
    "/demo/profile": {
      decision: "allowed",
      user: "demo-user",
      activity: "normal session"
    },
    "/demo/admin": {
      decision: "allowed_with_warning",
      message: "Admin panel reached"
    },
    "/demo/debug": {
      decision: "allowed_with_warning",
      message: "Debug endpoint response"
    },
    "/demo/internal": {
      decision: "allowed_with_warning",
      message: "Internal service metadata"
    },
    "/demo/api/export": {
      decision: "allowed_with_warning",
      message: "Export job queued"
    },
    "/demo/api/users/delete": {
      decision: "allowed_with_warning",
      message: "Delete request received"
    }
  };

  const responseBody = responses[url.pathname] || {
    decision: "allowed",
    message: "Generic demo route response",
    path: url.pathname
  };

  sendJson(res, event.level === "MEDIUM" ? 202 : 200, {
    ...responseBody,
    riskLevel: event.level,
    riskScore: event.score,
    reasons: event.reasons
  });
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/api/events") {
    sendJson(res, 200, { events: engine.getRecentEvents() });
    return;
  }

  if (url.pathname === "/api/summary") {
    sendJson(res, 200, engine.getSummary());
    return;
  }

  if (url.pathname === "/api/baseline") {
    sendJson(res, 200, engine.getBaselineSnapshot());
    return;
  }

  if (url.pathname === "/api/analyst-summary") {
    sendJson(res, 200, engine.getAnalystSummary());
    return;
  }

  if (url.pathname === "/api/simulation" && req.method === "GET") {
    sendJson(res, 200, simulationState);
    return;
  }

  if (url.pathname === "/api/simulate/normal" && req.method === "POST") {
    const result = triggerSimulation("normal");
    sendJson(res, result.accepted ? 202 : 409, result);
    return;
  }

  if (url.pathname === "/api/simulate/attack" && req.method === "POST") {
    const result = triggerSimulation("attack");
    sendJson(res, result.accepted ? 202 : 409, result);
    return;
  }

  if (url.pathname === "/api/reset" && req.method === "POST") {
    if (simulationState.running) {
      sendJson(res, 409, {
        error: "Cannot reset while a simulation is running",
        state: simulationState
      });
      return;
    }

    engine.reset();
    resetSimulationState();
    sendJson(res, 200, {
      ok: true,
      message: "Detection engine and baseline cleared",
      summary: engine.getSummary(),
      simulation: simulationState
    });
    return;
  }

  if (url.pathname.startsWith("/demo/")) {
    try {
      const rawBody = await readBody(req);
      const features = extractFeatures(req, rawBody);
      const sessionId = resolveSessionId(req);
      const event = engine.analyze(sessionId, features);
      handleDemoEndpoint(req, res, event);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "GET") {
    serveStatic(req, res);
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    sendJson(res, 500, { error: error.message });
  });
});

server.listen(PORT, () => {
  console.log(`Threat Detection System running at http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log("Try: npm run simulate:normal  |  npm run simulate:attack");
});
