# Advanced Security Log Analyzer & Threat Mitigation System
# Author: Shiphrah
# Description: Detect threats, blacklist attackers, simulate account lockout
# CompTIA Security+ SOC Analyst Project

import re
import csv
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs.txt"
TXT_REPORT = "report.txt"
CSV_REPORT = "report.csv"
JSON_REPORT = "report.json"
BLACKLIST_FILE = "blacklist.txt"

failed_attempts = defaultdict(int)
success_attempts = defaultdict(int)
first_seen = {}
last_seen = {}

LOCKOUT_THRESHOLD = 5


def get_risk_level(attempts):

    if attempts >= 10:
        return "CRITICAL"
    elif attempts >= 5:
        return "HIGH"
    elif attempts >= 3:
        return "MEDIUM"
    elif attempts >= 1:
        return "LOW"
    else:
        return "SAFE"


def blacklist_ip(ip):

    with open(BLACKLIST_FILE, "a") as file:
        file.write(ip + "\n")

    print(f"[ACTION] IP Blacklisted: {ip}")


def analyze_logs():

    print("\n========== SECURITY LOG ANALYZER ==========")
    print("Monitoring Logs...\n")

    try:
        with open(LOG_FILE, "r") as file:
            logs = file.readlines()

        for line in logs:

            timestamp_match = re.search(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)

            ip_match = re.search(
                r'IP:(\d+\.\d+\.\d+\.\d+)', line)

            if not ip_match or not timestamp_match:
                continue

            ip = ip_match.group(1)

            timestamp = datetime.strptime(
                timestamp_match.group(1),
                "%Y-%m-%d %H:%M:%S"
            )

            if ip not in first_seen:
                first_seen[ip] = timestamp

            last_seen[ip] = timestamp

            if "LOGIN FAILED" in line:
                failed_attempts[ip] += 1

            elif "LOGIN SUCCESS" in line:
                success_attempts[ip] += 1

        generate_reports()

    except FileNotFoundError:
        print("Log file not found")


def generate_reports():

    suspicious_count = 0
    json_data = []

    with open(TXT_REPORT, "w") as txt, \
         open(CSV_REPORT, "w", newline="") as csvfile:

        csv_writer = csv.writer(csvfile)

        csv_writer.writerow([
            "IP Address",
            "Failed Attempts",
            "Success Attempts",
            "Risk Level",
            "First Seen",
            "Last Seen"
        ])

        txt.write("Security Incident Report\n")
        txt.write("=========================\n\n")

        for ip in failed_attempts:

            attempts = failed_attempts[ip]
            success = success_attempts[ip]
            risk = get_risk_level(attempts)

            duration = last_seen[ip] - first_seen[ip]

            txt.write(f"IP Address: {ip}\n")
            txt.write(f"Failed Attempts: {attempts}\n")
            txt.write(f"Successful Attempts: {success}\n")
            txt.write(f"Risk Level: {risk}\n")
            txt.write(f"Attack Duration: {duration}\n")

            alert = "None"

            if attempts >= LOCKOUT_THRESHOLD:

                alert = "Account Lockout Triggered"
                txt.write("[ALERT] Account Lockout Triggered\n")

                blacklist_ip(ip)
                suspicious_count += 1

            elif attempts >= 3 and success > 0:

                alert = "Possible Account Compromise"
                txt.write("[ALERT] Possible Account Compromise\n")

                suspicious_count += 1

            txt.write("\n")

            csv_writer.writerow([
                ip,
                attempts,
                success,
                risk,
                first_seen[ip],
                last_seen[ip]
            ])

            json_data.append({
                "ip": ip,
                "failed_attempts": attempts,
                "success_attempts": success,
                "risk_level": risk,
                "first_seen": str(first_seen[ip]),
                "last_seen": str(last_seen[ip]),
                "alert": alert
            })

    with open(JSON_REPORT, "w") as jsonfile:
        json.dump(json_data, jsonfile, indent=4)

    print("\n========== SOC DASHBOARD ==========")
    print(f"Total IPs analyzed: {len(failed_attempts)}")
    print(f"Suspicious IPs: {suspicious_count}")
    print(f"Blacklist file: {BLACKLIST_FILE}")
    print(f"TXT Report: {TXT_REPORT}")
    print(f"CSV Report: {CSV_REPORT}")
    print(f"JSON Report: {JSON_REPORT}")
    print("====================================\n")


analyze_logs()
