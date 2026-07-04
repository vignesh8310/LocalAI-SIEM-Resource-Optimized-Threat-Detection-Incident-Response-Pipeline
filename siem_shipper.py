import time
import os
import re
import requests
import json

# =====================================================================
# CONFIGURATION
# =====================================================================
# Place your Discord Webhook URL inside the quotes below for one-way alerts
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"

# Pre-compiled high-speed pattern scanner to protect the GPU from normal system noise
SUSPICIOUS_KEYWORDS = re.compile(r'(failed|critical|unauthorized|refused|denied|blocked)', re.IGNORECASE)

# =====================================================================
# PHASE 4: DISCORD ALERT DISPATCHER
# =====================================================================
def send_discord_alert(log_entry, ai_verdict):
    """
    Formats the AI's structural JSON analysis into a rich Discord embed card
    and transmits it via an outbound webhook request to your server channel.
    """
    if not DISCORD_WEBHOOK_URL or "YOUR_DISCORD" in DISCORD_WEBHOOK_URL:
        print("[!] Alert generated but Discord Webhook URL is not configured.")
        return

    severity = ai_verdict.get("severity", "Medium").upper()
    reason = ai_verdict.get("reason", "No reason provided by AI.")
    
    # Selecting the left vertical sidebar color based on severity levels (Decimal values)
    color_map = {
        "LOW": 3066993,       # Green
        "MEDIUM": 15105570,   # Orange
        "HIGH": 15158332,     # Red
        "CRITICAL": 10038562  # Dark Red
    }
    embed_color = color_map.get(severity, 15105570)

    # Building the structural API payload for Discord's interface
    payload = {
        "username": "AI-SIEM Core Analyst",
        "avatar_url": "https://i.imgur.com/S863Xlh.png", 
        "embeds": [
            {
                "title": f"🚨 SECURITY ALERT - SEVERITY: {severity}",
                "description": f"**Raw Log Evaluated:**\n`{log_entry}`",
                "color": embed_color,
                "fields": [
                    {
                        "name": "🧠 AI Analysis & Reasoning",
                        "value": reason,
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "AI-SIEM Local Detection Engine v1.0"
                },
                "timestamp": json.dumps(time.strftime('%Y-%m-%dT%H:%M:%SZ'))[1:-1]
            }
        ]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("[+] Alert successfully dispatched to Discord channel!")
        else:
            print(f"[!] Discord API returned status code: {response.status_code}")
    except Exception as e:
        print(f"[!] Failed to dispatch alert: {str(e)}")

# =====================================================================
# PHASE 3: LOCAL AI CORE
# =====================================================================
def analyze_log_with_ai(log_entry):
    """
    Sends the suspicious log string to your local Ollama port executing llama3.2:3b.
    The strict prompt enforces pure JSON output formatting.
    """
    ollama_url = "http://localhost:11434/api/generate"
    
    system_prompt = (
        "You are an expert SOC Analyst. Analyze the provided log entry. "
        "Respond ONLY in a valid JSON object with three keys: 'threat_detected' (true/false), "
        "'severity' (Low, Medium, High, Critical), and 'reason' (a brief explanation). "
        "Do not include any conversational text, markdown formatting, or backticks outside the raw JSON."
    )
    
    payload = {
        "model": "llama3.2:3b",
        "prompt": f"{system_prompt}\n\nLog to analyze: {log_entry}",
        "stream": False
    }
    
    try:
        response = requests.post(ollama_url, json=payload)
        response_data = response.json()
        ai_response = response_data.get("response", "").strip()
        return json.loads(ai_response)
    except Exception as e:
        return {"error": f"AI Engine Analysis Failed: {str(e)}"}

# =====================================================================
# PHASE 2: PRE-FILTER
# =====================================================================
def pre_filter_log(log_entry):
    if SUSPICIOUS_KEYWORDS.search(log_entry):
        return True
    return False

# =====================================================================
# PHASE 1: INGESTION ENGINE
# =====================================================================
def monitor_log_file(file_path):
    print(f"[*] AI-Powered SIEM Pipeline Active...")
    print(f"[*] Target AI Architecture: llama3.2:3b (GPU Optimized)")
    print(f"[*] Engine listening on: {file_path}\n" + "-"*50)
    
    with open(file_path, 'r') as file:
        file.seek(0, os.SEEK_END)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            log_entry = line.strip()
            if log_entry:
                if pre_filter_log(log_entry):
                    print(f"\n[!] ESCALATING TO AI CORE: {log_entry}")
                    
                    ai_result = analyze_log_with_ai(log_entry)
                    
                    print("--- AI VERDICT REPORT ---")
                    print(json.dumps(ai_result, indent=4))
                    print("-------------------------")
                    
                    if ai_result.get("threat_detected") is True:
                        send_discord_alert(log_entry, ai_result)
                else:
                    print(f"[.] Filtered (Normal Activity): {log_entry}")

if __name__ == "__main__":
    target_log_path = "simulated_network.log"
    if not os.path.exists(target_log_path):
        with open(target_log_path, 'w') as f:
            f.write("--- Custom SIEM Pipeline Init ---\n")
            
    monitor_log_file(target_log_path)
