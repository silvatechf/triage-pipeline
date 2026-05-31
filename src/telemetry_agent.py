import time
import requests
import random

API_URL = "http://127.0.0.1:5000/api/v1/triage"

def send_telemetry_burst(target_ip, abuse_score, attack_type="automated"):
    """
    Simulates endpoint network events and dispatches payload bursts to the Triage API.
    """
    print(f"\n[!] Initiating telemetry dispatch simulation for IP: {target_ip}")
    print(f"    Mode: {attack_type.upper()}")
    print("-" * 65)

    # We will simulate 4 log events to feed the backend entropy calculator
    for i in range(4):
        current_time = time.time()
        
        payload = {
            "target_ioc": target_ip,
            "timestamp": current_time,
            "abuse_score": abuse_score
        }
        
        try:
            response = requests.post(API_URL, json=payload)
            if response.status_code in [200, 201]:
                data = response.json()
                metrics = data["analysis_results"]["metrics"]
                triage = data["analysis_results"]["incident_response_triage"]
                
                print(f"[Event {i+1}] Risk Score: {metrics['calculated_risk_score']} -> {triage['verdict']}")
            else:
                print(f"[!] Server returned error status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("[X] Critical Error: Cannot connect to the Triage API Server. Is it running?")
            return

        # Behavioral Timing Injection
        if attack_type == "automated":
            # Strict deterministic interval (low variance/standard deviation)
            time.sleep(0.1) 
        else:
            # Erratic human interval (high variance/entropy)
            time.sleep(random.uniform(1.2, 2.8))

if __name__ == "__main__":
    print("=" * 65)
    print("🚀 TELEMETRY SIMULATION AGENT - PIPELINE TESTBED")
    print("=" * 65)
    
    # TEST CASE 1: Simulated Machine-Driven Brute Force (High Threat Intel + High Automation)
    send_telemetry_burst(
        target_ip="185.220.101.5", 
        abuse_score="100/100", 
        attack_type="automated"
    )
    
    time.sleep(2) # Cooldown between tests
    
    # TEST CASE 2: Simulated Human Error / False Positive (Low Threat Intel + High Variable Cadence)
    send_telemetry_burst(
        target_ip="192.168.1.50", 
        abuse_score="0/100", 
        attack_type="human"
    )
