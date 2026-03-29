def trust_score(device):
    score = 100

    # IoT devices start with lower trust
    if device["type"] == "iot":
        score -= 30

    # Port scanning detected
    if device["scanning"]:
        score -= 50

    # Too many LAN connections = suspicious
    if device["lan_connections"] > 5:
        score -= 20

    # Unknown vendor
    if device["vendor"] == "Unknown":
        score -= 10

    return score

# Test
devices = [
    {"name": "cam1",     "type": "iot", "scanning": False, "lan_connections": 1, "vendor": "nginx"},
    {"name": "bulb1",    "type": "iot", "scanning": False, "lan_connections": 0, "vendor": "mosquitto"},
    {"name": "attacker", "type": "iot", "scanning": True,  "lan_connections": 15, "vendor": "Unknown"},
]

for d in devices:
    score = trust_score(d)
    status = "✅ TRUSTED" if score >= 60 else "⚠️  RESTRICTED" if score >= 40 else "🚨 QUARANTINE"
    print(f"{d['name']:12} | Score: {score:3} | {status}")
