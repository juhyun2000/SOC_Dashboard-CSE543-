from datetime import datetime, timedelta
import random

NUM_LOGS = 100_000

severities = ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL']
messages = [
    'User login successful',
    'Failed to connect to database',
    'Disk usage exceeded 90%',
    'Service restarted successfully',
    'Unauthorized access attempt detected',
    'Scheduled backup completed',
    'File not found during sync',
    'Memory usage normal',
    'CPU load high',
    'Configuration file updated'
]

start_time = datetime.now() - timedelta(days=1)

log_lines = []
for i in range(NUM_LOGS):
    log_time = start_time + timedelta(seconds=i) 
    timestamp_str = log_time.strftime('%m.%d.%Y %H:%M:%S')
    severity = random.choice(severities)
    message = random.choice(messages)
    line = f"{timestamp_str} {severity} {message}"
    log_lines.append(line)

log_file_path = "/Users/pai/Downloads/generated_logs.log"
with open(log_file_path, "w") as f:
    f.write("\n".join(log_lines))
