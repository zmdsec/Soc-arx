def calculate_risk(event_type):
    scores = {
        "port_scan": 30,
        "phishing": 50,
        "brute_force": 70,
        "malware": 90
    }
    return scores.get(event_type, 10)
