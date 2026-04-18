# Demo Checklist

## Before Presentation

- Run `npm start`
- Open `http://localhost:3000`
- Click `Reset Engine`
- Keep browser zoom around 90-100% so timeline + analyst panel fit cleanly

## Live Demo Flow

1. Show empty/clean dashboard after Reset Engine.
2. Click `Simulate Normal Traffic`.
3. Point to:
   - LOW-risk events
   - Learned Route Baseline filling up
   - Analyst Summary staying calm/no active incident
4. Click `Simulate Attack Traffic`.
5. Point to:
   - Live Attack Timeline spike
   - HIGH-risk event rows
   - threat intent labels
   - suspicious focus session `intruder-zero-day`
   - analyst recommendation text
6. Click `Reset Engine` to prove the demo can be replayed instantly.

## If Something Goes Wrong

- If buttons look stuck, wait a few seconds: simulation state disables buttons until the run finishes.
- If port 3000 is already in use, stop the old server with `Ctrl + C` and rerun `npm start`.
- If the dashboard looks stale, hard refresh the browser once.

## Short Closing Line

“This MVP shows how behavior baselines, route-sequence anomaly detection, and explainable risk scoring can provide an early warning layer for unknown attack behavior without depending on predefined signatures.”
