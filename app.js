const eventsBody = document.getElementById("eventsBody");
const totalRequests = document.getElementById("totalRequests");
const baselineRoutes = document.getElementById("baselineRoutes");
const highestRisk = document.getElementById("highestRisk");
const highCount = document.getElementById("highCount");
const sessionsList = document.getElementById("sessionsList");
const routeBars = document.getElementById("routeBars");
const intentBars = document.getElementById("intentBars");
const riskTimeline = document.getElementById("riskTimeline");
const lastUpdated = document.getElementById("lastUpdated");
const analystTimestamp = document.getElementById("analystTimestamp");
const incidentSeverity = document.getElementById("incidentSeverity");
const incidentStatus = document.getElementById("incidentStatus");
const incidentIntent = document.getElementById("incidentIntent");
const incidentNarrative = document.getElementById("incidentNarrative");
const incidentRecommendation = document.getElementById("incidentRecommendation");
const incidentFindings = document.getElementById("incidentFindings");
const focusSession = document.getElementById("focusSession");
const simulationStatus = document.getElementById("simulationStatus");
const normalBtn = document.getElementById("normalBtn");
const attackBtn = document.getElementById("attackBtn");
const resetBtn = document.getElementById("resetBtn");
const timelineCtx = riskTimeline.getContext("2d");

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function renderEvents(events) {
  if (!events.length) {
    eventsBody.innerHTML = `
      <tr>
        <td colspan="6" class="reason">No traffic yet. Run a normal or attack simulation to stream live detections.</td>
      </tr>
    `;
    return;
  }

  eventsBody.innerHTML = events
    .slice(0, 80)
    .map(
      (event) => `
        <tr>
          <td>${new Date(event.timestamp).toLocaleTimeString()}</td>
          <td>${event.sessionId}</td>
          <td>${event.method} ${event.path}</td>
          <td><span class="intent-tag">${event.intent || "Normal Behavior"}</span></td>
          <td><span class="risk-pill risk-${event.level}">${event.level} · ${event.score}</span></td>
          <td class="reason">${event.reasons.join(" · ")}</td>
        </tr>
      `
    )
    .join("");
}

function renderSessions(sessions) {
  if (!sessions.length) {
    sessionsList.innerHTML = `<p class="session-meta">No session traffic observed yet.</p>`;
    return;
  }

  sessionsList.innerHTML = sessions
    .map(
      (session) => `
        <div class="session-row">
          <div>
            <p class="session-id">${session.sessionId}</p>
            <p class="session-meta">
              ${session.lastPath || "No route"} · Age ${session.sessionAgeSeconds || 1}s
              <br />
              ${session.recentReasons[0] || "Stable baseline behavior"}
            </p>
            <span class="session-intent">${session.recentIntent || "Normal Behavior"}</span>
          </div>
          <span class="risk-pill risk-${session.riskScore >= 70 ? "HIGH" : session.riskScore >= 35 ? "MEDIUM" : "LOW"}">
            ${session.riskScore}
          </span>
        </div>
      `
    )
    .join("");
}

function renderRoutes(routes) {
  if (!routes.length) {
    routeBars.innerHTML = `<p class="session-meta">Baseline starts learning after low-risk requests arrive.</p>`;
    return;
  }

  const maxCount = Math.max(...routes.map((route) => route.count), 1);

  routeBars.innerHTML = routes
    .map((route) => {
      const width = Math.max(6, Math.round((route.count / maxCount) * 100));
      return `
        <div class="route-bar">
          <div class="route-label">
            <span>${route.path}</span>
            <span class="route-count">${route.count}</span>
          </div>
          <div class="track"><div class="fill" style="width:${width}%"></div></div>
        </div>
      `;
    })
    .join("");
}

function renderIntents(intents) {
  if (!intents.length) {
    intentBars.innerHTML = `<p class="session-meta">Threat categories appear here as soon as events are scored.</p>`;
    return;
  }

  const maxCount = Math.max(...intents.map((item) => item.count), 1);

  intentBars.innerHTML = intents
    .map((item) => {
      const width = Math.max(8, Math.round((item.count / maxCount) * 100));
      return `
        <div class="route-bar">
          <div class="route-label">
            <span>${item.intent}</span>
            <span class="route-count">${item.count}</span>
          </div>
          <div class="track"><div class="fill" style="width:${width}%"></div></div>
        </div>
      `;
    })
    .join("");
}

function drawTimeline(events) {
  const width = riskTimeline.width;
  const height = riskTimeline.height;
  const paddingX = 40;
  const paddingY = 28;
  const chartWidth = width - paddingX * 2;
  const chartHeight = height - paddingY * 2;
  const points = events.slice(0, 60).reverse();

  timelineCtx.clearRect(0, 0, width, height);

  timelineCtx.strokeStyle = "rgba(148, 163, 184, 0.18)";
  timelineCtx.lineWidth = 1;
  [0, 25, 50, 75, 100].forEach((score) => {
    const y = paddingY + chartHeight - (score / 100) * chartHeight;
    timelineCtx.beginPath();
    timelineCtx.moveTo(paddingX, y);
    timelineCtx.lineTo(width - paddingX, y);
    timelineCtx.stroke();
    timelineCtx.fillStyle = "#64748b";
    timelineCtx.font = "12px Inter, sans-serif";
    timelineCtx.fillText(String(score), 8, y + 4);
  });

  if (points.length < 2) {
    timelineCtx.fillStyle = "#94a3b8";
    timelineCtx.font = "16px Inter, sans-serif";
    timelineCtx.fillText("Run normal traffic, then attack traffic, to see the risk curve spike here.", 48, height / 2);
    return;
  }

  const coords = points.map((event, index) => {
    const x = paddingX + (index / Math.max(points.length - 1, 1)) * chartWidth;
    const y = paddingY + chartHeight - (event.score / 100) * chartHeight;
    return { x, y, level: event.level };
  });

  const gradient = timelineCtx.createLinearGradient(0, paddingY, 0, height - paddingY);
  gradient.addColorStop(0, "rgba(239, 68, 68, 0.45)");
  gradient.addColorStop(0.5, "rgba(251, 191, 36, 0.2)");
  gradient.addColorStop(1, "rgba(34, 197, 94, 0.08)");

  timelineCtx.beginPath();
  timelineCtx.moveTo(coords[0].x, height - paddingY);
  coords.forEach((point) => timelineCtx.lineTo(point.x, point.y));
  timelineCtx.lineTo(coords[coords.length - 1].x, height - paddingY);
  timelineCtx.closePath();
  timelineCtx.fillStyle = gradient;
  timelineCtx.fill();

  timelineCtx.beginPath();
  coords.forEach((point, index) => {
    if (index === 0) timelineCtx.moveTo(point.x, point.y);
    else timelineCtx.lineTo(point.x, point.y);
  });
  timelineCtx.strokeStyle = "#38bdf8";
  timelineCtx.lineWidth = 3;
  timelineCtx.stroke();

  coords.forEach((point) => {
    timelineCtx.beginPath();
    timelineCtx.arc(point.x, point.y, point.level === "HIGH" ? 5 : 3.5, 0, Math.PI * 2);
    timelineCtx.fillStyle = point.level === "HIGH"
      ? "#ef4444"
      : point.level === "MEDIUM"
        ? "#f59e0b"
        : "#22c55e";
    timelineCtx.fill();
  });
}

function renderAnalystSummary(summary) {
  const severity = summary.severity || "LOW";
  incidentSeverity.className = `risk-pill risk-${severity}`;
  incidentSeverity.textContent = severity;
  incidentStatus.textContent = summary.status || "No active incident";
  incidentIntent.textContent = summary.dominantIntent || "Normal Behavior";
  incidentNarrative.textContent = summary.narrative || "No analyst summary available yet.";
  incidentRecommendation.textContent = summary.recommendation || "Monitor traffic and rerun simulation if needed.";
  focusSession.textContent = summary.focusSession || "None";

  incidentFindings.innerHTML = (summary.keyFindings || [])
    .map((finding) => `<li>${finding}</li>`)
    .join("");

  analystTimestamp.textContent = summary.latestEventTime
    ? `Latest suspicious event: ${new Date(summary.latestEventTime).toLocaleString()}`
    : "Auto-generated from recent medium/high-risk events";
}

async function refreshDashboard() {
  try {
    const [summary, eventsPayload, baseline, simulation, analystSummary] = await Promise.all([
      fetchJson("/api/summary"),
      fetchJson("/api/events"),
      fetchJson("/api/baseline"),
      fetchJson("/api/simulation"),
      fetchJson("/api/analyst-summary")
    ]);

    totalRequests.textContent = summary.totalRequests;
    baselineRoutes.textContent = summary.baselineRoutes;
    highestRisk.textContent = summary.highestRisk;
    highCount.textContent = summary.highCount;

    renderEvents(eventsPayload.events || []);
    drawTimeline(eventsPayload.events || []);
    renderAnalystSummary(analystSummary);
    renderSessions(summary.activeSessions || []);
    renderIntents(summary.topIntents || []);
    renderRoutes(baseline.routes || []);

    simulationStatus.textContent = simulation.running
      ? `${simulation.mode.toUpperCase()} Simulation Running`
      : simulation.message || "Live Engine Online";
    normalBtn.disabled = simulation.running;
    attackBtn.disabled = simulation.running;
    resetBtn.disabled = simulation.running;

    lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    lastUpdated.textContent = `Dashboard error: ${error.message}`;
  }
}

async function triggerSimulation(mode) {
  normalBtn.disabled = true;
  attackBtn.disabled = true;
  resetBtn.disabled = true;
  simulationStatus.textContent = `Launching ${mode.toUpperCase()} Simulation`;

  const response = await fetch(`/api/simulate/${mode}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  });

  if (!response.ok && response.status !== 409) {
    simulationStatus.textContent = `Failed to launch ${mode} simulation`;
  }

  await refreshDashboard();
}

async function resetEngine() {
  normalBtn.disabled = true;
  attackBtn.disabled = true;
  resetBtn.disabled = true;
  simulationStatus.textContent = "Resetting Engine";

  const response = await fetch("/api/reset", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  });

  if (!response.ok) {
    simulationStatus.textContent = "Reset blocked while simulation is running";
  }

  await refreshDashboard();
}

normalBtn.addEventListener("click", () => triggerSimulation("normal"));
attackBtn.addEventListener("click", () => triggerSimulation("attack"));
resetBtn.addEventListener("click", resetEngine);

refreshDashboard();
setInterval(refreshDashboard, 1500);