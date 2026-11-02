import argparse                    
import os                           
import random
from datetime import datetime, timedelta

#  Default output: project-root/app/elis_industries_logs.log (relative to this file)
#  Docker mounts project-root/app as /app, so the app can read it right away
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "project-root", "app", "elis_industries_logs.log")

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


def main():
    # Define the options
    ap = argparse.ArgumentParser(description="Generate synthetic security event logs")
    ap.add_argument("--count", type=int, default=1_000_000, help="number of log lines")
    ap.add_argument("--out", default=DEFAULT_OUT, help="output file path")
    ap.add_argument("--seed", type=int, default=None, help="random seed (same seed = same logs)")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    start_time = datetime.now() - timedelta(seconds=args.count)   # logs end at "now"
    log_lines = []
    print("Generating logs...")

    for i in range(args.count):                                   # NUM_LOGS → args.count
        timestamp = start_time + timedelta(seconds=i)
        timestamp_str = timestamp.strftime('%m.%d.%Y %H:%M:%S')

        severity = random.choices(severities, weights=[0.6, 0.2, 0.15, 0.05])[0]
        component = random.choice(components)
        user = random.choice(users)
        ip = random_ip()

        template = random.choice(messages_by_severity[severity])
        message = template.format(user=user, component=component, ip=ip)
        log_lines.append(f"{timestamp_str} {severity} {component} {message}")

    with open(args.out, "w") as f:                                # log_path → args.out
        f.write("\n".join(log_lines))

    print(f"✅ Done. {args.count:,} logs saved to {args.out}")


if __name__ == "__main__":                                        # runs only when executed directly
    main()
