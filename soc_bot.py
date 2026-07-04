import time
import os
import re
import requests
import json
import sqlite3
import threading
import discord
from discord.ext import commands

# =====================================================================
# CONFIGURATION & INFRASTRUCTURE INIT
# =====================================================================
# Place your Discord Developer Application Bot Token inside the quotes below
DISCORD_BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"
OLLAMA_URL = "http://localhost:11434/api/generate"
TARGET_LOG_PATH = "simulated_network.log"
DB_FILE = 'siem_history.db'

def init_db():
    """Establishes the SQLite database to ensure log persistence."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_text TEXT,
            severity TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize intents for the Interactive Bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Pre-compiled high-speed regular expression scanner to minimize GPU load
SUSPICIOUS_KEYWORDS = re.compile(r'(failed|critical|unauthorized|refused|denied|blocked)', re.IGNORECASE)

# =====================================================================
# COGNITIVE DETECTIONS & INGESTION (THREAD 1)
# =====================================================================
def analyze_log_with_ai(log_entry):
    """Dispatches anomalies to local llama3.2:3b via an optimized JSON prompt."""
    system_prompt = (
        "You are an expert SOC Analyst. Analyze the provided log entry. "
        "Respond ONLY in a valid JSON object with three keys: 'threat_detected' (true/false), "
        "'severity' (Low, Medium, High, Critical), and 'reason' (a brief explanation). "
        "Do not include any conversational text, markdown formatting, or backticks outside the raw JSON."
    )
    payload = {"model": "llama3.2:3b", "prompt": f"{system_prompt}\n\nLog to analyze: {log_entry}", "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        ai_text = response.json().get("response", "").strip()
        return json.loads(ai_text)
    except Exception as e:
        return {"threat_detected": False, "severity": "Medium", "reason": f"AI Parsing failed: {str(e)}"}

def save_to_siem_db(log_text, ai_result):
    """Commits security alerts directly into active SQLite table records."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        "INSERT INTO security_logs (timestamp, log_text, severity, reason) VALUES (?, ?, ?, ?)",
        (current_time, log_text, ai_result.get("severity", "Medium"), ai_result.get("reason", ""))
    )
    conn.commit()
    conn.close()

def log_monitor_worker():
    """Background operational daemon that watches live log files for threat signatures."""
    init_db()
    
    if not os.path.exists(TARGET_LOG_PATH):
        with open(TARGET_LOG_PATH, 'w') as f:
            f.write("--- Custom SIEM Pipeline Init ---\n")
            
    print(f"[*] Ingestion Core listening dynamically on: {TARGET_LOG_PATH}")
    
    with open(TARGET_LOG_PATH, 'r') as file:
        file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            log_entry = line.strip()
            if log_entry:
                if SUSPICIOUS_KEYWORDS.search(log_entry):
                    print(f"\n[!] ANOMALY ESCALATED: {log_entry}")
                    
                    ai_verdict = analyze_log_with_ai(log_entry)
                    
                    if ai_verdict.get("threat_detected") is True:
                        print("[+] Threat Verified. Writing to Database memory...")
                        save_to_siem_db(log_entry, ai_verdict)
                else:
                    print(f"[.] Filtered (Normal Activity): {log_entry}")

# =====================================================================
# INTERACTIVE DISCORD BOT COMMANDS (THREAD 2)
# =====================================================================
@bot.event
async def on_ready():
    print(f"[+] Interactive SOC Analyst Bot is ONLINE as {bot.user.name}!\n" + "-"*50)

@bot.command(name='metrics')
async def threat_metrics(ctx):
    """Command: !metrics -> Pulls basic quantitative analytics from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE severity='CRITICAL'")
    crit = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE severity='HIGH'")
    high = cursor.fetchone()[0]
    
    conn.close()
    await ctx.send(f"📊 **Current SIEM Database Metrics:**\n🔴 Critical Incidents: **{crit}**\n🟠 High Alerts: **{high}**")

@bot.command(name='summary')
async def system_summary(ctx):
    """Command: !summary -> Injecting database data into local AI context (RAG) with length protection."""
    await ctx.send("🧠 Interrogating local database telemetry logs... Please wait.")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, severity, log_text FROM security_logs ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        await ctx.send("✅ Database indicates zero threats logged recently.")
        return
        
    db_context = ""
    for r in rows:
        db_context += f"[{r[0]}] Severity: {r[1]} | Log: {r[2]}\n"
        
    system_prompt = (
        "You are a Senior Security Director. Summarize the following security incidents extracted from our database. "
        "Point out the primary source IPs, types of attacks seen, and give a short recommendation on how to secure the host. "
        "CRITICAL: Keep your entire response concise and under 1500 characters total."
    )
    
    payload = {"model": "llama3.2:3b", "prompt": f"{system_prompt}\n\nDatabase Context:\n{db_context}", "stream": False}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        ai_response = response.json().get("response", "").strip()
        
        if len(ai_response) > 1900:
            for i in range(0, len(ai_response), 1900):
                await ctx.send(ai_response[i:i+1900])
        else:
            await ctx.send(f"📋 **AI Incident Analysis Summary:**\n{ai_response}")
            
    except Exception as e:
        await ctx.send(f"❌ Failed to reach local model core: {str(e)}")

@bot.command(name='fix')
async def incident_response_guide(ctx, *, threat_name: str):
    """Command: !fix <threat> -> Generates a technical playbook for mitigation."""
    await ctx.send(f"🔍 Consulting local intelligence core for threat mitigation: **{threat_name}**...")
    
    system_prompt = (
        "You are an expert Incident Response engineer. Provide a brief, bulleted, step-by-step "
        "technical guide on how a security administrator can mitigate and remediate the following threat. "
        "CRITICAL: Keep your entire response concise and under 1500 characters total."
    )
    payload = {"model": "llama3.2:3b", "prompt": f"{system_prompt}\n\nThreat to mitigate: {threat_name}", "stream": False}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        ai_guide = response.json().get("response", "").strip()
        
        if len(ai_guide) > 1900:
            for i in range(0, len(ai_guide), 1900):
                await ctx.send(ai_guide[i:i+1900])
        else:
            await ctx.send(f"🛡️ **Incident Response Playbook for {threat_name}:**\n{ai_guide}")
    except Exception as e:
        await ctx.send(f"❌ Failed to generate mitigation guide: {str(e)}")

@bot.command(name='lookup')
async def ip_threat_lookup(ctx, ip_address: str):
    """Command: !lookup <IP> -> Leverages external threat OSINT endpoints for reputation audits."""
    await ctx.send(f"🌐 Querying global threat intelligence mapping for: `{ip_address}`...")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data.get("status") == "success":
            report = (
                f"🔍 **Threat Intel Report for {ip_address}:**\n"
                f"📍 Country: **{data.get('country')}**\n"
                f"🏢 ISP: **{data.get('isp')}**\n"
                f"🛡️ Organization: **{data.get('org')}**"
            )
            await ctx.send(report)
        else:
            await ctx.send("❌ Could not retrieve geolocation infrastructure details for that IP address.")
    except Exception as e:
        await ctx.send(f"❌ Threat lookup engine connectivity error: {str(e)}")

@bot.command(name='investigate')
async def investigate_attacker(ctx, keyword: str):
    """Command: !investigate <IP/User> -> Focuses forensic extraction on single criteria indicators with chunking safety."""
    await ctx.send(f"🕵️‍♂️ Scanning SIEM database for historical database signatures matching: `{keyword}`...")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, severity, log_text FROM security_logs WHERE log_text LIKE ?", (f'%{keyword}%',))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        await ctx.send(f"✅ No incidents involving explicit criteria `{keyword}` match active database memory.")
        return
        
    context = "".join([f"[{r[0]}] Log: {r[2]}\n" for r in rows[:5]])
    system_prompt = (
        f"You are a Forensic Investigator. Analyze these specific logs related to the target '{keyword}'. "
        "Explain the attacker's objective, what techniques they used, and if they succeeded. "
        "CRITICAL: Keep your entire response brief, structural, and under 1500 characters total."
    )
    payload = {"model": "llama3.2:3b", "prompt": f"{system_prompt}\n\nTarget Logs:\n{context}", "stream": False}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        ai_response = response.json().get("response", "").strip()
        
        header = f"📋 **Forensic Timeline Summary for {keyword}:**\n"
        await ctx.send(header)
        
        if len(ai_response) > 1900:
            for i in range(0, len(ai_response), 1900):
                await ctx.send(ai_response[i:i+1900])
        else:
            await ctx.send(ai_response)
            
    except Exception as e:
        await ctx.send(f"❌ Analysis parsing runtime failure: {str(e)}")

# =====================================================================
# ENGINE EXECUTION CONTROL
# =====================================================================
if __name__ == "__main__":
    # Spawning Thread 1 for log tracking dependencies
    log_thread = threading.Thread(target=log_monitor_worker, daemon=True)
    log_thread.start()
    
    # Executing Bot Connection framework in Main Thread
    try:
        bot.run(DISCORD_BOT_TOKEN)
    except discord.errors.LoginFailure:
        print("[!] Execution Failure: Your DISCORD_BOT_TOKEN is invalid.")
