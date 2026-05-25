import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_markdown(self, profile):
        if not profile:
            return None
        
        attacker_ip = profile['attacker_ip']
        filename = f"report_{attacker_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        report = f"""# 🛡️ MIRAGE Forensic Report
## Incident: {attacker_ip}
**Date du rapport :** {datetime.now().isoformat()}

---

### 📊 Résumé de l'attaquant
- **IP :** {attacker_ip}
- **Première activité :** {profile['first_activity']}
- **Dernière activité :** {profile['last_activity']}
- **Nombre d'événements :** {profile['total_events']}
- **Score de risque :** {profile['risk_score']}/100

### 🎯 Tactiques MITRE ATT&CK Détectées
{self._format_list(profile['detected_tactics'])}

### 🛠️ Techniques Utilisées
{self._format_list(profile['techniques'])}

---

### ⏳ Timeline de l'attaque
| Timestamp | Composant | Action | MITRE |
|-----------|-----------|--------|-------|
"""
        for e in profile['timeline']:
            report += f"| {e['timestamp']} | {e['component']} | {e['action']} | {e['mitre_id']} ({e['mitre_tactic']}) |\n"
            
        report += """
---
*Généré automatiquement par MIRAGE — Système de Défense Active*
"""
        
        with open(filepath, "w") as f:
            f.write(report)
            
        return filepath

    def _format_list(self, items):
        if not items:
            return "- Aucune détectée"
        return "\n".join([f"- {i}" for i in items])
