import os
import math
import statistics
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==============================================================================
# CONFIGURATION & THREAT INTELLIGENCE MATRIX
# ==============================================================================
# In-memory database to store tracking timestamps per IP for behavior analysis
IP_TELEMETRY_DB = {}

# Risk thresholds
RISK_THRESHOLD_CRITICAL = 80
RISK_THRESHOLD_SUSPICIOUS = 50

MITRE_MATRIX = {
    "tactic": "Credential Access",
    "technique_id": "T1110",
    "technique_name": "Brute Force"
}

def calculate_behavioral_anomaly(timestamps):
    """
    Analyzes the entropy of authentication intervals.
    Automated tools (e.g., Hydra) have deterministic time deltas (low standard deviation).
    Human errors display erratic timing (high standard deviation/entropy).
    """
    if len(timestamps) < 3:
        return 50.0  # Baseline risk for isolated attempts

    # Calculate time differentials between consecutive log entries
    intervals = []
    for i in range(len(timestamps) - 1):
        intervals.append(timestamps[i+1] - timestamps[i])

    try:
        std_dev = statistics.stdev(intervals)
        mean_interval = statistics.mean(intervals)
        
        # If standard deviation is extremely low, it's a machine-driven automated attack
        if std_dev < 0.15 and mean_interval < 1.5:
            return 95.0  # Confirmed automated brute force script
        elif std_dev < 0.5:
            return 75.0  # Highly suspicious systematic pattern
        else:
            return 30.0  # Human anomaly signature (Variable cadence)
    except statistics.StatisticsError:
        return 50.0

@app.route("/api/v1/triage", methods=["POST"])
def triage_incident():
    """
    REST API Endpoint that ingests telemetry events from endpoints or SIEM agents.
    Performs real-time behavioral analysis to filter out false positives.
    """
    data = request.get_json()

    if not data or "target_ioc" not in data or "timestamp" not in data:
        return jsonify({"error": "Invalid telemetry payload structure"}), 400

    target_ioc = data.get("target_ioc")
    current_timestamp = float(data.get("timestamp"))
    abuse_score_raw = data.get("abuse_score", "0/100")
    
    # Extract numerical value from abuse score string (e.g., "100/100" -> 100)
    try:
        abuse_score = int(abuse_score_raw.split("/")[0])
    except (ValueError, IndexError):
        abuse_score = 0

    # Feed telemetry database for time-delta calculation
    if target_ioc not in IP_TELEMETRY_DB:
        IP_TELEMETRY_DB[target_ioc] = []
    
    IP_TELEMETRY_DB[target_ioc].append(current_timestamp)
    
    # Keep only the last 10 records to optimize memory and focus on active bursts
    if len(IP_TELEMETRY_DB[target_ioc]) > 10:
        IP_TELEMETRY_DB[target_ioc].pop(0)

    # Compute behavioral analytics based on timing patterns
    behavior_score = calculate_behavioral_anomaly(IP_TELEMETRY_DB[target_ioc])

    # Dynamic Risk Scoring Equation (60% Behavior Analysis + 40% Global Threat Intel)
    final_risk_score = (behavior_score * 0.6) + (abuse_score * 0.4)
    final_risk_score = min(100.0, max(0.0, final_risk_score))

    # Decision Engine: Establish Verdict and Analyst Response Action
    if final_risk_score >= RISK_THRESHOLD_CRITICAL:
        verdict = "CRITICAL THREAT - AUTOMATED ATTACK DETECTED"
        analyst_action = "ACTIVE RESPONSE TRIGGERED: Inject firewall DROP rule immediately."
        status_code = 201
    elif final_risk_score >= RISK_THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS ACTIVITY - POTENTIAL MALICIOUS ATTEMPT"
        analyst_action = "LOG ENRICHMENT: Escalate alert priority within SIEM dashboard."
        status_code = 200
    else:
        verdict = "LOW RISK - PROBABLE FALSE POSITIVE"
        analyst_action = "DISMISS ALERT: Record telemetry for baseline analytics."
        status_code = 200

    # Build the high-fidelity response payload without marketing labels
    triage_report = {
        "engine_metadata": {
            "pipeline_version": "1.0.0",
            "mitre_mapping": MITRE_MATRIX
        },
        "analysis_results": {
            "target_ioc": target_ioc,
            "metrics": {
                "behavioral_score": f"{behavior_score:.2f}/100",
                "threat_intel_score": f"{abuse_score}/100",
                "calculated_risk_score": f"{final_risk_score:.2f}/100"
            },
            "incident_response_triage": {
                "verdict": verdict,
                "analyst_action": analyst_action
            }
        }
    }

    return jsonify(triage_report), status_code

if __name__ == "__main__":
    print("[*] Starting Threat Detection Pipeline Server...")
    app.run(host="127.0.0.1", port=5000, debug=False)
