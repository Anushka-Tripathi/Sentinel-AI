const { BehaviorBaseline } = require("./baselineStore");

const MAX_RECENT_EVENTS = 250;
const BASELINE_WARMUP_REQUESTS = 12;
const HIGH_RISK_ROUTES = [
  "/demo/admin",
  "/demo/debug",
  "/demo/internal",
  "/demo/api/export",
  "/demo/api/users/delete"
];

class ThreatDetectionEngine {
  constructor() {
    this.baseline = new BehaviorBaseline();
    this.sessions = new Map();
    this.events = [];
    this.totalRequests = 0;
    this.lowCount = 0;
    this.mediumCount = 0;
    this.highCount = 0;
    this.intentCounts = new Map();
  }

  analyze(sessionId, features) {
    const session = this.sessions.get(sessionId) || {
      lastPath: null,
      timestamps: [],
      riskScore: 0,
      recentReasons: [],
      recentIntent: "Normal Behavior",
      firstSeenAt: features.timestamp
    };
    const previousPath = session.lastPath;

    session.timestamps = session.timestamps.filter((ts) => features.timestamp - ts <= 10000);
    session.timestamps.push(features.timestamp);

    const anomalies = [];
    const routeStats = this.baseline.getRouteStats(features.path);
    const burstCount = session.timestamps.length;
    const transitionKnown = this.baseline.hasTransition(previousPath, features.path);
    const unseenRouteAfterWarmup = !this.baseline.hasRoute(features.path)
      && this.baseline.observationCount >= BASELINE_WARMUP_REQUESTS;

    if (burstCount >= 25) {
      anomalies.push({
        score: 40,
        intent: "Automated Recon / Bot Burst",
        reason: `Request burst detected: ${burstCount} requests within 10 seconds`
      });
    } else if (burstCount >= 12) {
      anomalies.push({
        score: 25,
        intent: "Automated Recon / Bot Burst",
        reason: `Elevated request frequency: ${burstCount} requests within 10 seconds`
      });
    }

    if (features.suspiciousMarkerCount > 0) {
      const markerScore = Math.min(40, features.suspiciousMarkerCount * 15);
      anomalies.push({
        score: markerScore,
        intent: classifyPayloadIntent(features),
        reason: `Suspicious payload/path markers found: ${features.suspiciousMarkerCount}`
      });
    }

    if (HIGH_RISK_ROUTES.includes(features.path) && features.role !== "admin") {
      anomalies.push({
        score: 35,
        intent: "Privilege Escalation Attempt",
        reason: `Privileged endpoint accessed by ${features.role} session`
      });
    }

    if (previousPath && !transitionKnown && this.baseline.observationCount >= 4) {
      anomalies.push({
        score: 20,
        intent: "Sequence Anomaly",
        reason: `Unusual route transition: ${previousPath} -> ${features.path}`
      });
    }

    if (routeStats && features.payloadSize > Math.max(120, routeStats.avgPayloadSize * 3)) {
      anomalies.push({
        score: 15,
        intent: "Payload Manipulation",
        reason: `Payload size spike: ${features.payloadSize} bytes vs baseline ${routeStats.avgPayloadSize.toFixed(1)}`
      });
    }

    if (features.payloadSize > 100 && features.payloadEntropy >= 4.5) {
      anomalies.push({
        score: 15,
        intent: "Obfuscated Payload",
        reason: `High-entropy payload structure detected: entropy ${features.payloadEntropy}`
      });
    }

    if (unseenRouteAfterWarmup) {
      anomalies.push({
        score: 10,
        intent: "Endpoint Discovery",
        reason: `Previously unseen route after baseline warm-up: ${features.path}`
      });
    }

    if (features.method !== "GET" && features.role === "guest" && HIGH_RISK_ROUTES.includes(features.path)) {
      anomalies.push({
        score: 10,
        intent: "Unauthorized State Mutation",
        reason: `State-changing ${features.method} request from guest role on sensitive route`
      });
    }

    const score = Math.min(100, anomalies.reduce((total, anomaly) => total + anomaly.score, 0));
    const reasons = anomalies.map((anomaly) => anomaly.reason);
    const intent = inferDominantIntent(anomalies);

    let level = "LOW";
    if (score >= 70) {
      level = "HIGH";
    } else if (score >= 35) {
      level = "MEDIUM";
    }

    if (level === "LOW") this.lowCount += 1;
    if (level === "MEDIUM") this.mediumCount += 1;
    if (level === "HIGH") this.highCount += 1;
    this.intentCounts.set(intent, (this.intentCounts.get(intent) || 0) + 1);

    session.riskScore = score;
    session.recentReasons = reasons;
    session.recentIntent = intent;

    if (level === "LOW") {
      this.baseline.observe(previousPath, features);
    }

    session.lastPath = features.path;
    this.sessions.set(sessionId, session);

    this.totalRequests += 1;
    const event = {
      id: `${features.timestamp}-${this.totalRequests}`,
      timestamp: new Date(features.timestamp).toISOString(),
      sessionId,
      method: features.method,
      path: features.path,
      role: features.role,
      score,
      level,
      intent,
      reasons: reasons.length ? reasons : ["Behavior matches learned baseline"],
      payloadSize: features.payloadSize,
      suspiciousMarkerCount: features.suspiciousMarkerCount,
      entropy: features.payloadEntropy,
      transition: {
        fromPath: previousPath,
        toPath: features.path,
        known: transitionKnown
      }
    };

    this.events.unshift(event);
    if (this.events.length > MAX_RECENT_EVENTS) {
      this.events.length = MAX_RECENT_EVENTS;
    }

    return event;
  }

  getRecentEvents(limit = 80) {
    return this.events.slice(0, limit);
  }

  getSummary() {
    const activeSessions = [...this.sessions.entries()].map(([sessionId, data]) => ({
      sessionId,
      riskScore: data.riskScore,
      lastPath: data.lastPath,
      recentIntent: data.recentIntent,
      recentReasons: data.recentReasons,
      sessionAgeSeconds: Math.max(1, Math.round((Date.now() - data.firstSeenAt) / 1000))
    }));

    const highestRisk = activeSessions.reduce((max, session) => Math.max(max, session.riskScore), 0);

    return {
      totalRequests: this.totalRequests,
      baselineRoutes: this.baseline.routeStats.size,
      highestRisk,
      lowCount: this.lowCount,
      mediumCount: this.mediumCount,
      highCount: this.highCount,
      activeSessions: activeSessions.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10),
      topIntents: [...this.intentCounts.entries()]
        .filter(([intent]) => intent !== "Normal Behavior")
        .map(([intent, count]) => ({ intent, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
    };
  }

  getAnalystSummary() {
    const recentThreats = this.events
      .filter((event) => event.level !== "LOW")
      .slice(0, 40);

    if (!recentThreats.length) {
      return {
        status: "No active incident",
        severity: "LOW",
        narrative: "Traffic currently matches the learned baseline. No suspicious medium/high-risk activity has been observed in the recent event window.",
        keyFindings: [
          "No suspicious route transitions or privilege violations in the recent window.",
          "Baseline learning is active and updating from low-risk requests."
        ],
        recommendation: "Run normal traffic first to warm the baseline, then launch attack simulation to validate anomaly detection.",
        focusSession: "None",
        dominantIntent: "Normal Behavior",
        latestEventTime: null
      };
    }

    const highRiskCount = recentThreats.filter((event) => event.level === "HIGH").length;
    const mediumRiskCount = recentThreats.filter((event) => event.level === "MEDIUM").length;
    const sessionCounts = new Map();
    const intentCounts = new Map();
    const reasonCounts = new Map();

    for (const event of recentThreats) {
      sessionCounts.set(event.sessionId, (sessionCounts.get(event.sessionId) || 0) + 1);
      intentCounts.set(event.intent, (intentCounts.get(event.intent) || 0) + 1);
      for (const reason of event.reasons.slice(0, 3)) {
        reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
      }
    }

    const focusSession = sortCountMap(sessionCounts)[0]?.[0] || "Unknown";
    const dominantIntent = sortCountMap(intentCounts)[0]?.[0] || "Unknown Threat Pattern";
    const topReasons = sortCountMap(reasonCounts)
      .slice(0, 3)
      .map(([reason]) => reason);

    return {
      status: highRiskCount > 0 ? "Active threat suspected" : "Suspicious behavior under review",
      severity: highRiskCount > 0 ? "HIGH" : "MEDIUM",
      narrative: `${dominantIntent} activity is concentrated in session ${focusSession}. The engine observed ${highRiskCount} high-risk and ${mediumRiskCount} medium-risk events in the recent window, indicating behavior that deviates from the learned baseline.`,
      keyFindings: topReasons.length ? topReasons : ["Anomalous traffic detected with limited supporting context."],
      recommendation: highRiskCount > 0
        ? `Immediately throttle or isolate session ${focusSession}, inspect recent requests for ${dominantIntent.toLowerCase()}, and rotate any potentially exposed credentials.`
        : `Monitor session ${focusSession}, lower the risk threshold if needed, and verify whether this ${dominantIntent.toLowerCase()} pattern is legitimate business traffic.`,
      focusSession,
      dominantIntent,
      latestEventTime: recentThreats[0].timestamp
    };
  }

  getBaselineSnapshot() {
    return this.baseline.snapshot();
  }

  reset() {
    this.baseline = new BehaviorBaseline();
    this.sessions.clear();
    this.events = [];
    this.totalRequests = 0;
    this.lowCount = 0;
    this.mediumCount = 0;
    this.highCount = 0;
    this.intentCounts.clear();
  }
}

function classifyPayloadIntent(features) {
  const pathText = `${features.path} ${features.query}`.toLowerCase();
  if (pathText.includes("../") || pathText.includes("..\\")) {
    return "Directory Traversal Probe";
  }
  if (pathText.includes("debug") || pathText.includes("internal")) {
    return "Internal Endpoint Recon";
  }
  if (features.suspiciousMarkerCount >= 2) {
    return "Injection Payload Attempt";
  }
  return "Suspicious Payload";
}

function inferDominantIntent(anomalies) {
  if (!anomalies.length) return "Normal Behavior";

  const grouped = new Map();
  for (const anomaly of anomalies) {
    grouped.set(anomaly.intent, (grouped.get(anomaly.intent) || 0) + anomaly.score);
  }

  return [...grouped.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

function sortCountMap(countMap) {
  return [...countMap.entries()].sort((a, b) => b[1] - a[1]);
}

module.exports = { ThreatDetectionEngine };
