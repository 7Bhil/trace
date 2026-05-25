import sys
import os
import argparse
from profiler import TraceProfiler
from report_generator import ReportGenerator

class TraceOrchestrator:
    def __init__(self):
        self.profiler = TraceProfiler()
        self.generator = ReportGenerator()

    def profile_and_report(self, attacker_ip):
        print(f"[*] 🕵️ MIRAGE TRACE : Analyse de l'attaquant {attacker_ip}...")
        
        # 1. Profiling
        profile = self.profiler.analyze_attacker(attacker_ip)
        if not profile:
            print(f"[!] Aucun événement trouvé pour {attacker_ip}.")
            return
            
        # 2. Génération de rapport
        filepath = self.generator.generate_markdown(profile)
        print(f"[+] Rapport généré : {filepath}")
        
        # 3. Optionnel : Envoyer un événement "Rapport Prêt" au Cloud
        if self.profiler.db and self.profiler.db.db is not None:
            self.profiler.db.insert_event({
                "component": "trace",
                "type": "forensic_report_ready",
                "severity": "info",
                "target": {"ip": attacker_ip},
                "message": f"Rapport forensique prêt pour {attacker_ip}.",
                "data": {"report_path": filepath}
            })

def main():
    parser = argparse.ArgumentParser(description="Mirage Trace Engine - Forensic & Profiling Tool")
    parser.add_argument("ip", help="Attacker IP to profile")
    args = parser.parse_args()
    
    trace = TraceOrchestrator()
    trace.profile_and_report(args.ip)

if __name__ == "__main__":
    main()
