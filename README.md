# Triage Pipeline

A defensive cybersecurity lab demonstrating a small Flask API for ingesting simulated authentication telemetry and assigning a heuristic risk score based on event timing and a supplied abuse score.

> **Scope:** educational prototype, not a production SOC/SIEM integration or a validated brute-force detector. Timing patterns alone cannot reliably distinguish automated attacks from human activity. The MITRE ATT&CK mapping is contextual, not proof that an attack occurred.

## What it demonstrates

- A REST endpoint for receiving JSON telemetry.
- An explainable heuristic based on intervals between events.
- A combined score using behavioral timing (60%) and a caller-supplied abuse score (40%).
- Structured JSON output with a verdict and contextual MITRE ATT&CK reference.
- A client script simulating two event patterns for local testing.

## Architecture

- `src/api_server.py` — Flask endpoint at `POST /api/v1/triage`, in-memory event history, heuristic scoring, and JSON response.
- `src/telemetry_agent.py` — sends simulated events to the local API.

The implementation stores recent timestamps in process memory keyed by `target_ioc`. State is lost when the server restarts and is not shared across multiple workers. The input abuse score is supplied by the client and is not independently verified.

## Requirements

- Python 3.10 or newer recommended.
- Install dependencies from `requirements.txt`.

## Run locally (Windows PowerShell)

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src/api_server.py
```

The API listens on `http://127.0.0.1:5000` by default.

Open a second PowerShell window, activate the same environment, then run:

```powershell
.\.venv\Scripts\Activate.ps1
python src/telemetry_agent.py
```

The agent submits local simulation data to the API and prints the returned risk score. Use only synthetic data in this lab.

## Example request

```powershell
$body = @{
    target_ioc = "lab-example"
    timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000
    abuse_score = "20/100"
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
    -Uri "http://127.0.0.1:5000/api/v1/triage" `
    -ContentType "application/json" `
    -Body $body
```

## Important limitations and safety

- The current scoring logic is a teaching heuristic; it has no calibrated dataset, measured precision/recall, or validated thresholds.
- The API has no authentication, durable storage, rate limiting, or schema validation beyond basic required-field checks. Do not expose it to a public or untrusted network.
- The API uses in-memory state and is intended for a single local process.
- An analyst action is descriptive text only. The project does **not** install firewall rules or automatically block traffic.
- Included IP addresses and event patterns are simulation examples, not threat-intelligence claims.
- Only test against systems and data you own or are explicitly authorized to assess.

## Project status

This repository is a learning lab. Dependency installation and execution should be verified in your environment before relying on the examples. Automated tests and CI are not currently included.

## License

Check the repository's licensing status before redistributing or reusing the project.
