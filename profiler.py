import os
import sys
import json
from datetime import datetime

# Add parent directory for database_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

MITRE_MAPPING = {
    "port_scan": {"id": "T1595.001", "tactic": "Reconnaissance", "name": "Active Scanning: Scanning IP Blocks"},
    "vulnerability_found": {"id": "T1595.002", "tactic": "Reconnaissance", "name": "Active Scanning: Vulnerability Scanning"},
    "attack_signature": {"id": "T1210", "tactic": "Exploitation", "name": "Exploitation of Remote Services"},
    "bruteforce": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    "dns_threat": {"id": "T1071.004", "tactic": "Command and Control", "name": "Application Layer Protocol: DNS"}
}

class TraceProfiler:
    def __init__(self):
        self.db = MongoAtlasManager() if MongoAtlasManager else None

    def analyze_attacker(self, attacker_ip):
        """Reconstitue l'activité d'un attaquant et le profile"""
        if not self.db or self.db.db is None:
            return None
        
        # Récupérer tous les événements liés à cette IP
        events = list(self.db.db['events'].find({
            "$or": [
                {"target.ip": attacker_ip},
                {"attacker.ip": attacker_ip},
                {"ip": attacker_ip}
            ]
        }).sort('timestamp', 1))

        if not events:
            return None

        timeline = []
        tactics_used = set()
        techniques = []

        for e in events:
            e_type = e.get('type')
            mitre = MITRE_MAPPING.get(e_type, {"id": "Unknown", "tactic": "Unknown", "name": "Unknown"})
            
            timeline.append({
                "timestamp": e.get('timestamp'),
                "component": e.get('component'),
                "action": e.get('message'),
                "mitre_id": mitre['id'],
                "mitre_tactic": mitre['tactic']
            })
            
            if mitre['tactic'] != "Unknown":
                tactics_used.add(mitre['tactic'])
                techniques.append(mitre['name'])

        profile = {
            "attacker_ip": attacker_ip,
            "first_activity": events[0]['timestamp'],
            "last_activity": events[-1]['timestamp'],
            "total_events": len(events),
            "detected_tactics": list(tactics_used),
            "techniques": list(set(techniques)),
            "timeline": timeline,
            "risk_score": len(events) * 10 # Simple score
        }
        
        return profile

if __name__ == "__main__":
    if len(sys.argv) > 1:
        profiler = TraceProfiler()
        p = profiler.analyze_attacker(sys.argv[1])
        print(json.dumps(p, indent=4))
