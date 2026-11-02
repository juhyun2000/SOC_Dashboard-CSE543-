import random
from datetime import datetime, timedelta

NUM_LOGS = 1_000_000
users = ['jsmith', 'amanda', 'ravi', 'lee', 'admin', 'guest', 'emma', 'john_d', 'sylvia', 'ramon']
components = ['AuthService', 'PaymentService', 'BackupManager', 'Firewall', 'Antivirus', 'Kernel', 'DBConnector', 'WebApp', 'PatchDaemon']
severities = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
company_name = "Elis Industries"

messages_by_severity = {
    'INFO': [
        "User {user} logged in successfully",
        "Scheduled backup completed on {component}",
        "Security patch applied by {user}",
        "File config.yml accessed by {user}",
        "Session started for {user} on {component}"
    ],
    'WARNING': [
        "Multiple failed login attempts for {user} from IP {ip}",
        "Unusual outbound traffic detected from {component}",
        "User {user} attempted to access restricted file",
        "High memory usage detected on {component}"
    ],
    'ERROR': [
        "Database connection failed on {component}",
        "Service crash reported on {component}",
        "Job scheduler failed to run nightly task",
        "Log rotation error on {component}"
    ],
    'CRITICAL': [
        "Antivirus detected malware signature on {component}",
        "User {user} attempted unauthorized privilege escalation",
        "Kernel panic: system halted on {component}",
        "Possible data exfiltration detected from {component} to IP {ip}"
    ]
}

def random_ip():
    return f"{random.randint(10, 255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

start_time = datetime.now() - timedelta(days=7)
log_lines = []

print("Generating logs...")

for i in range(NUM_LOGS):
    timestamp = start_time + timedelta(seconds=i)
    timestamp_str = timestamp.strftime('%m.%d.%Y %H:%M:%S')

    severity = random.choices(severities, weights=[0.6, 0.2, 0.15, 0.05])[0]
    component = random.choice(components)
    user = random.choice(users)
    ip = random_ip()

    template = random.choice(messages_by_severity[severity])
    message = template.format(user=user, component=component, ip=ip)

    log_line = f"{timestamp_str} {severity} {component} {message}"
    log_lines.append(log_line)

log_path = "/Users/pai/Downloads/elis_industries_logs.log"
with open(log_path, "w") as f:
    f.write("\n".join(log_lines))

print(f"✅ Done. {NUM_LOGS:,} logs saved to {log_path}")