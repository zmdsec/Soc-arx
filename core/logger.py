from datetime import datetime

def log_event(event_type, message):
    with open("logs/events.log", "a") as f:
        f.write(f"{datetime.now()} | {event_type} | {message}\n")
