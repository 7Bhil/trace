import sys
import os
import argparse
import time
import threading
from profiler import TraceProfiler
from report_generator import ReportGenerator

class TraceOrchestrator:
    def __init__(self):
        self.profiler = TraceProfiler()
        self.generator = ReportGenerator()
        self.running = False
        self.db = self.profiler.db

    def profile_and_report(self, attacker_ip):
        print(f"[*] 🕵️ MIRAGE TRACE : Analyse de l'attaquant {attacker_ip}...")
        
        # 1. Profiling
        profile = self.profiler.analyze_attacker(attacker_ip)
        if not profile:
            print(f"[!] Aucun événement trouvé pour {attacker_ip}.")
            return None
            
        # 2. Génération de rapport
        filepath = self.generator.generate_markdown(profile)
        print(f"[+] Rapport généré : {filepath}")
        
        # 3. Optionnel : Envoyer un événement "Rapport Prêt" au Cloud
        if self.db and self.db.db is not None:
            self.db.insert_event({
                "component": "trace",
                "type": "forensic_report_ready",
                "severity": "info",
                "target": {"ip": attacker_ip},
                "message": f"Rapport forensique prêt pour {attacker_ip}.",
                "data": {"report_path": filepath}
            })
        return filepath

    def start_daemon(self):
        """Lance Trace en mode écoute pour générer des rapports à la demande"""
        print(f"[*] 🕵️ MIRAGE TRACE : Démon d'analyse lancé.")
        self.running = True
        
        # Lancer le heartbeat
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        
        while self.running:
            try:
                if self.db:
                    commands = self.db.get_pending_commands("trace")
                    for cmd in commands:
                        action = cmd.get("action")
                        target = cmd.get("target_ip")
                        cmd_id = cmd.get("_id")
                        
                        if action == "generate_report" and target:
                            print(f"[!] ORDRE REÇU : Générer rapport pour {target}")
                            path = self.profile_and_report(target)
                            if path:
                                self.db.update_command_status(cmd_id, "executed", result=f"Rapport généré: {path}")
                            else:
                                self.db.update_command_status(cmd_id, "failed", result="Aucune donnée trouvée")
                                
                time.sleep(10)
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                print(f"[!] Erreur Trace Daemon : {e}")
                time.sleep(20)

    def _heartbeat_loop(self):
        while self.running:
            if self.db:
                self.db.send_heartbeat("trace")
            time.sleep(60)

def main():
    parser = argparse.ArgumentParser(description="Mirage Trace Engine - Forensic & Profiling Tool")
    parser.add_argument("ip", nargs='?', help="Attacker IP to profile")
    parser.add_argument("--daemon", action="store_true", help="Run in command listener mode")
    args = parser.parse_args()
    
    trace = TraceOrchestrator()
    
    if args.daemon:
        trace.start_daemon()
    elif args.ip:
        trace.profile_and_report(args.ip)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
