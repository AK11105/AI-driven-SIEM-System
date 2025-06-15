import json
import re
from confluent_kafka import Consumer

# Kafka Consumer Configuration
consumer = Consumer({
    'bootstrap.servers': '192.168.37.132:9092',
    'group.id': 'log-consumer-group',
    'auto.offset.reset': 'latest'
    # 'auto.offset.reset': 'earliest'
})

consumer.subscribe(['server-logs'])

# Regex Patterns
auth_pattern = r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>[\w\-.]+) (?P<process>[\w\-]+)(\[(?P<pid>\d+)\])?: (?P<message>.*)'
syslog_pattern = r'(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>[\w\-.]+) (?P<program>[\w\-.]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)'
kern_pattern = r'(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>[\w\-.]+) kernel: \[(?P<uptime>[\d\.]+)\] (?P<message>.+)'

# Parser Functions
def parse_auth_log(log):
    match = re.match(auth_pattern, log)
    return match.groupdict() if match else None

def parse_syslog_log(log):
    match = re.match(syslog_pattern, log)
    return match.groupdict() if match else None

def parse_kern_log(log):
    match = re.match(kern_pattern, log)
    return match.groupdict() if match else None

def should_drop_log(parsed_log):
    return parsed_log.get("program") == "filebeat" or parsed_log.get("process") == "filebeat"

# Format output like syslog
def format_log(parsed_log):
    timestamp = parsed_log.get("timestamp", "unknown")
    hostname = parsed_log.get("hostname", "unknown")
    program = parsed_log.get("program") or parsed_log.get("process", "unknown")
    pid = parsed_log.get("pid")
    message = parsed_log.get("message", "")

    if pid:
        return f"{timestamp} {hostname} {program}[{pid}]: {message}"
    else:
        return f"{timestamp} {hostname} {program}: {message}"

# Process structured JSON logs
def process_json_log(log_json):
    try:
        log_data = json.loads(log_json)

        message = log_data.get("message", "")
        source_file = log_data.get("log", {}).get("file", {}).get("path", "unknown")
        hostname = log_data.get("host", {}).get("hostname", "unknown")
        timestamp = log_data.get("@timestamp", "unknown")

        # Drop verbose or irrelevant logs
        if "filebeat" in message.lower() or "monitoring" in message.lower():
            return

        # Try parsing embedded message
        for parser in [parse_auth_log, parse_syslog_log, parse_kern_log]:
            parsed = parser(message)
            if parsed:
                if should_drop_log(parsed):
                    return
                print(format_log(parsed))
                return

        # If unstructured but meaningful, print basic info
        short_message = message.strip()
        if short_message:
            print(f"{timestamp} {hostname} {source_file}: {short_message}")

    except json.JSONDecodeError:
        print("Invalid JSON log:", log_json)

# Process raw or structured log
def process_log(log):
    try:
        json.loads(log)
        process_json_log(log)
        return
    except json.JSONDecodeError:
        pass

    auth_parsed = parse_auth_log(log)
    if auth_parsed:
        if should_drop_log(auth_parsed):
            return
        print(format_log(auth_parsed))
        return

    syslog_parsed = parse_syslog_log(log)
    if syslog_parsed:
        if should_drop_log(syslog_parsed):
            return
        print(format_log(syslog_parsed))
        return

    kern_parsed = parse_kern_log(log)
    if kern_parsed:
        print(format_log(kern_parsed))
        return

    # Fallback for unknown raw logs
    print("Unrecognized Log:", log)

# Main loop
print("Listening for logs...")

try:
    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            print("Error:", msg.error())
            continue

        log = msg.value().decode('utf-8')
        process_log(log)

except KeyboardInterrupt:
    print("Exiting...")
finally:
    consumer.close()