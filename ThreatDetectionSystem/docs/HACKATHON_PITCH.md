# Hackathon Pitch Notes

## One-Line Pitch

Sentinel AI is a behavior-based threat detection system that flags suspicious request patterns and potential zero-day-like activity without relying on fixed attack signatures.

## Problem

Most security systems are reactive because they depend on known signatures, blacklists, or pre-documented exploit patterns. If an attacker uses a new route sequence, a novel payload shape, or a previously unseen abuse pattern, signature-only defenses may miss it.

The core challenge is: **how do we detect suspicious behavior when we do not already know the exact attack string or exploit signature?**

## Solution

Our system learns a baseline of normal application behavior and continuously scores incoming requests for anomalies such as burst traffic, unusual route transitions, suspicious payload structure, and unauthorized access to privileged endpoints.

Instead of asking “Have we seen this exact attack before?”, the engine asks “Does this session behave abnormally compared with learned application flow and role expectations?”

## System Architecture for PPT

### 1. Ingress & Feature Extraction Layer

A Node.js HTTP interception layer captures each request and extracts behavior features:

- route path and HTTP method
- session identifier and user role
- payload size and payload entropy
- suspicious markers in route/query/body
- route transition from previous request to current request

### 2. Behavior Profiling Engine

Low-risk traffic is used to update an in-memory baseline of normal route statistics and transition patterns. This creates a lightweight behavioral profile of how users and admin sessions typically move through the app.

### 3. Heuristic Anomaly Scoring Layer

Each request receives a score from 0-100 based on:

- request burst rate
- suspicious payload markers
- unknown route transitions
- payload size deviation
- high-entropy body patterns
- guest access to sensitive/admin routes

The output is mapped to LOW / MEDIUM / HIGH risk with explainable reasons.

### 4. Response + Analyst Layer

High-risk requests are blocked in the demo endpoint flow, medium-risk requests are allowed with warning, and all events are streamed to a dashboard with:

- live event table
- attack timeline chart
- threat intent breakdown
- active session risk cards
- auto-generated analyst summary and recommended response

## Technical Moat

- **Signature-independent detection:** does not need a known malware or exploit database
- **Sequence-aware analysis:** flags suspicious user journeys, not just suspicious single requests
- **Explainable outputs:** every alert includes intent + reasons + analyst summary
- **Real-time demoability:** one-click normal/attack simulations make the invisible backend logic visible
- **Lightweight integration path:** can be packaged as Node.js middleware for existing web apps

## Suggested PPT Slide Structure

1. Problem: Why signature-only security fails for unknown threats
2. Solution: Behavior-based anomaly detection and risk scoring
3. System Architecture: 4-layer pipeline diagram
4. Live Dashboard: screenshots of timeline, events, and analyst summary
5. Technical Moat: signature independence + explainability + sequence analysis
6. Impact & Future Scope: middleware packaging, Redis persistence, optional LLM summarization

## 2-Minute Demo Script

**0:00 - 0:20 | Setup**

“This is Sentinel AI, a behavior-based threat detection system. Our goal is to detect suspicious activity without relying on known attack signatures, by learning what normal request behavior looks like and flagging deviations in real time.”

**0:20 - 0:50 | Baseline Learning**

“First I’ll click Reset Engine and then Simulate Normal Traffic. These are normal user/admin flows like login, browsing products, cart updates, and profile access. You can see the route baseline starts learning and most events remain LOW risk because the traffic follows expected behavior.”

**0:50 - 1:30 | Attack Simulation**

“Now I’ll launch Simulate Attack Traffic. This synthetic attacker hits debug/internal/admin-style endpoints, sends traversal and injection-like payloads, and then performs rapid burst scanning. Notice the Live Attack Timeline spikes sharply, several events are marked HIGH, and the engine blocks those requests with 403 responses.”

**1:30 - 1:50 | Explainability**

“The important part is that the system does not just say ‘blocked.’ It explains why: unusual route transitions, suspicious payload markers, privileged endpoint access from a guest session, and burst behavior. The Threat Analyst Summary converts that into an incident narrative, dominant intent, focus session, and recommended response.”

**1:50 - 2:00 | Closing**

“So the key idea is moving from signature-only detection to signature-independent behavioral anomaly detection, giving an early warning layer for potentially unknown or zero-day-like attack behavior.”

## Good Judge Q&A Answers

### Is this claiming perfect zero-day detection?

No. The correct framing is **early-warning anomaly detection for potentially unknown attacks**. It reduces reliance on signatures, but false positives and model tuning still matter.

### How do you define “normal”?

The baseline is built from low-risk traffic by tracking route statistics, average payload size/entropy, and route transition patterns. Once enough observations are collected, deviations from this baseline increase the risk score.

### Why not use only ML?

For a hackathon MVP, heuristic scoring is more explainable, deterministic, and easier to demo reliably. ML or LLM layers can be added later for adaptive baselines and richer summaries.

### What are the limitations?

- In-memory state resets on server restart
- Heuristic thresholds need tuning to reduce false positives
- This prototype simulates app traffic rather than sitting behind a real production app gateway
- A real deployment should add persistence, authentication context, rate-control policy, and distributed state
