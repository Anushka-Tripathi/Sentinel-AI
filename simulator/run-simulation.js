const { runScenario } = require("./scenarioRunner");

const mode = process.argv[2] || "normal";
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "localhost";

async function main() {
  console.log(`Running ${mode} traffic simulation against http://${HOST}:${PORT}`);

  await runScenario(mode, {
    host: HOST,
    port: PORT,
    onEvent: ({ mode: eventMode, sessionId, route, result }) => {
      const label = eventMode.toUpperCase();
      console.log(
        `[${label}] ${sessionId} ${route} -> ${result.status} ${result.body.riskLevel} (${result.body.riskScore})`
      );
      if (result.body.reasons && result.body.riskLevel !== "LOW") {
        console.log(`         reasons: ${result.body.reasons.join(" | ")}`);
      }
    }
  });

  console.log("Simulation complete. Refresh the dashboard to inspect the latest events.");
}

main().catch((error) => {
  console.error(`Simulation failed: ${error.message}`);
  process.exit(1);
});
