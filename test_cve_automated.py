#!/usr/bin/env python3
"""
CVE Testing Automation Tool for MoodleSec
Integrates automated CVE exploitation + scanner testing + dataset labeling

Usage:
    python test_cve_automated.py --cve CVE-2021-36393 --target http://localhost:8080
    python test_cve_automated.py --list-cves
    python test_cve_automated.py --cve CVE-2021-36393 --skip-exploit --scan-only
"""

import os
import sys
import json
import subprocess
import requests
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Color output support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = MAGENTA = ""
    class Style:
        BRIGHT = RESET_ALL = ""


class CVETester:
    """Automated CVE testing and dataset integration"""
    
    CVE_DATABASE = {
        "CVE-2021-36393": {
            "name": "SQL Injection in Recent Courses",
            "severity": "Critical",
            "cvss": 9.8,
            "component": "blocks/recentlyaccessedcourses",
            "exploit_repo": "https://github.com/T0X1Cx/CVE-2021-36393-Exploit.git",
            "exploit_dir": "CVE-2021-36393-Exploit",
            "exploit_script": "exploit.py",
            "affected_versions": ["3.9.0", "3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5", "3.9.6", "3.9.7"],
            "attack_vector": "sort parameter",
            "required_privilege": "student",
            "scanner_detection_rate": 0.65
        },
        "CVE-2021-36394": {
            "name": "XSS in User Profile",
            "severity": "High",
            "cvss": 7.5,
            "component": "user/profile",
            "exploit_repo": None,  # Manual testing required
            "affected_versions": ["3.9.0", "3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5", "3.9.6", "3.9.7"],
            "attack_vector": "profile description field",
            "required_privilege": "authenticated user",
            "scanner_detection_rate": 0.80
        },
        "CVE-2020-14321": {
            "name": "SQL Injection in Forum",
            "severity": "Critical",
            "cvss": 8.8,
            "component": "mod/forum",
            "exploit_repo": None,
            "affected_versions": ["3.9.0", "3.9.1"],
            "attack_vector": "discussion parameter",
            "required_privilege": "student",
            "scanner_detection_rate": 0.70
        },
        "CVE-2023-28329": {
            "name": "XSS in Calendar",
            "severity": "High",
            "cvss": 7.1,
            "component": "calendar",
            "exploit_repo": None,
            "affected_versions": ["3.9.0", "3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5", "3.9.6", "3.9.7"],
            "attack_vector": "event name field",
            "required_privilege": "authenticated user",
            "scanner_detection_rate": 0.75
        },
        "CVE-2020-14318": {
            "name": "CSRF in Course Management",
            "severity": "High",
            "cvss": 7.5,
            "component": "course",
            "exploit_repo": None,
            "affected_versions": ["3.9.0", "3.9.1"],
            "attack_vector": "course creation",
            "required_privilege": "teacher",
            "scanner_detection_rate": 0.40
        }
    }
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir).resolve()
        self.ml_dir = self.base_dir / "ml"
        self.training_data_dir = self.ml_dir / "training_data" / "real_data"
        self.cve_tracker_path = self.ml_dir / "training_data" / "cve_tracker.json"
        self.progress_log_path = self.base_dir / "TRAINING_PROGRESS_LOG.md"
        
    def print_info(self, message: str):
        """Print info message"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
        
    def print_success(self, message: str):
        """Print success message"""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        
    def print_warning(self, message: str):
        """Print warning message"""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        
    def print_error(self, message: str):
        """Print error message"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
        
    def list_cves(self):
        """List all available CVEs"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Available CVEs for Testing{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        for cve_id, info in self.CVE_DATABASE.items():
            exploit_status = "✅ Automated" if info['exploit_repo'] else "⚠️ Manual"
            print(f"{Fore.YELLOW}{cve_id}{Style.RESET_ALL}")
            print(f"  Name: {info['name']}")
            print(f"  Severity: {info['severity']} (CVSS {info['cvss']})")
            print(f"  Component: {info['component']}")
            print(f"  Exploit: {exploit_status}")
            print(f"  Scanner Detection Rate: {info['scanner_detection_rate']*100:.0f}%")
            print()
    
    def clone_exploit(self, cve_id: str) -> bool:
        """Clone exploit repository if available"""
        cve_info = self.CVE_DATABASE.get(cve_id)
        if not cve_info or not cve_info['exploit_repo']:
            self.print_warning(f"No automated exploit available for {cve_id}")
            return False
        
        exploit_dir = self.base_dir / cve_info['exploit_dir']
        
        if exploit_dir.exists():
            self.print_info(f"Exploit already cloned: {exploit_dir}")
            return True
        
        self.print_info(f"Cloning exploit from {cve_info['exploit_repo']}")
        
        try:
            result = subprocess.run(
                ["git", "clone", cve_info['exploit_repo'], str(exploit_dir)],
                capture_output=True,
                text=True,
                cwd=str(self.base_dir)
            )
            
            if result.returncode != 0:
                self.print_error(f"Git clone failed: {result.stderr}")
                return False
            
            self.print_success(f"Exploit cloned to {exploit_dir}")
            
            # Install requirements if exists
            requirements = exploit_dir / "requirements.txt"
            if requirements.exists():
                self.print_info("Installing exploit dependencies...")
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
                    capture_output=True
                )
            
            return True
            
        except Exception as e:
            self.print_error(f"Failed to clone exploit: {e}")
            return False
    
    def run_exploit(self, cve_id: str, target_url: str, username: str, password: str) -> Optional[Dict]:
        """Run automated exploit and return results"""
        cve_info = self.CVE_DATABASE.get(cve_id)
        if not cve_info or not cve_info['exploit_repo']:
            return None
        
        exploit_dir = self.base_dir / cve_info['exploit_dir']
        exploit_script = exploit_dir / cve_info['exploit_script']
        
        if not exploit_script.exists():
            self.print_error(f"Exploit script not found: {exploit_script}")
            return None
        
        self.print_info(f"Running exploit: {cve_id}")
        self.print_info(f"Target: {target_url}")
        
        # For CVE-2021-36393, we need to modify the exploit to accept command line args
        # or parse its output. For now, we'll capture output and parse it.
        
        try:
            # Create a temporary input file for the exploit
            input_data = f"{target_url}\n{username}\n{password}\n"
            
            result = subprocess.run(
                [sys.executable, str(exploit_script)],
                input=input_data,
                capture_output=True,
                text=True,
                cwd=str(exploit_dir),
                timeout=60
            )
            
            output = result.stdout + result.stderr
            
            # Parse exploit output
            exploit_result = {
                "cve_id": cve_id,
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "evidence": [],
                "raw_output": output
            }
            
            # Check for success indicators
            if "Vulnerability confirmed" in output or "Exploitation successful" in output:
                exploit_result["success"] = True
                self.print_success(f"✅ Exploit successful! Vulnerability confirmed.")
            elif "Database name" in output:
                exploit_result["success"] = True
                # Extract database name
                for line in output.split('\n'):
                    if "Database name" in line or "Admin user" in line or "Admin hash" in line:
                        exploit_result["evidence"].append(line.strip())
                self.print_success(f"✅ Data extracted: {len(exploit_result['evidence'])} items")
            else:
                self.print_warning("❌ Exploit did not confirm vulnerability")
            
            return exploit_result
            
        except subprocess.TimeoutExpired:
            self.print_error("Exploit timeout (60s)")
            return None
        except Exception as e:
            self.print_error(f"Exploit execution failed: {e}")
            return None
    
    def scan_with_zap(self, target_url: str, cve_id: str) -> Optional[str]:
        """Run OWASP ZAP scan and return results file path"""
        self.print_info("Starting OWASP ZAP scan...")
        
        cve_info = self.CVE_DATABASE.get(cve_id)
        component = cve_info['component'] if cve_info else ""
        
        # Check if ZAP is running
        try:
            response = requests.get("http://localhost:8090/JSON/core/view/version/")
            zap_version = response.json().get('version', 'unknown')
            self.print_info(f"Connected to OWASP ZAP {zap_version}")
        except:
            self.print_error("OWASP ZAP not running on port 8090")
            self.print_info("Start ZAP with: zap.sh -daemon -port 8090 -config api.disablekey=true")
            return None
        
        # Spider the target
        scan_url = f"{target_url}/{component}" if component else target_url
        self.print_info(f"Spidering: {scan_url}")
        
        try:
            # Start spider
            response = requests.get(
                f"http://localhost:8090/JSON/spider/action/scan/",
                params={"url": scan_url}
            )
            scan_id = response.json().get('scan')
            
            # Wait for spider to complete
            while True:
                response = requests.get(
                    f"http://localhost:8090/JSON/spider/view/status/",
                    params={"scanId": scan_id}
                )
                status = int(response.json().get('status', 0))
                if status >= 100:
                    break
                print(f"Spider progress: {status}%", end='\r')
                time.sleep(2)
            
            self.print_success("Spider completed")
            
            # Start active scan
            self.print_info("Starting active scan (this may take 5-10 minutes)...")
            response = requests.get(
                f"http://localhost:8090/JSON/ascan/action/scan/",
                params={"url": scan_url, "recurse": "true"}
            )
            scan_id = response.json().get('scan')
            
            # Wait for active scan
            while True:
                response = requests.get(
                    f"http://localhost:8090/JSON/ascan/view/status/",
                    params={"scanId": scan_id}
                )
                status = int(response.json().get('status', 0))
                if status >= 100:
                    break
                print(f"Active scan progress: {status}%", end='\r')
                time.sleep(5)
            
            self.print_success("Active scan completed")
            
            # Export results
            output_file = self.base_dir / f"cve_{cve_id.replace('-', '_')}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            response = requests.get("http://localhost:8090/JSON/core/view/alerts/")
            
            with open(output_file, 'w') as f:
                json.dump(response.json(), f, indent=2)
            
            self.print_success(f"Scan results saved to {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.print_error(f"ZAP scan failed: {e}")
            return None
    
    def extract_finding(self, scan_file: str, cve_id: str, exploit_result: Optional[Dict]) -> Optional[Dict]:
        """Extract finding from scan results and create training sample"""
        cve_info = self.CVE_DATABASE.get(cve_id)
        if not cve_info:
            return None
        
        self.print_info(f"Extracting findings from {scan_file}")
        
        try:
            with open(scan_file, 'r') as f:
                scan_data = json.load(f)
            
            alerts = scan_data.get('alerts', [])
            
            # Search for relevant alert
            relevant_alert = None
            component = cve_info['component']
            
            for alert in alerts:
                alert_name = alert.get('alert', '').lower()
                alert_url = alert.get('url', '').lower()
                
                # Check if alert matches CVE
                if component in alert_url:
                    if cve_info['name'].lower().split()[0] in alert_name:  # e.g., "sql" in "sql injection"
                        relevant_alert = alert
                        break
            
            scanner_detected = relevant_alert is not None
            
            if scanner_detected:
                self.print_success(f"✅ Scanner detected vulnerability!")
            else:
                self.print_warning(f"⚠️ Scanner did NOT detect vulnerability")
            
            # Create training sample
            finding = {
                "finding": {
                    "category": cve_info['name'].split()[0] + " " + cve_info['name'].split()[1],  # e.g., "SQL Injection"
                    "severity": cve_info['severity'],
                    "url": relevant_alert['url'] if relevant_alert else f"http://localhost:8080/{component}",
                    "param": relevant_alert.get('param', cve_info['attack_vector']) if relevant_alert else cve_info['attack_vector'],
                    "description": relevant_alert.get('description', cve_info['name']) if relevant_alert else cve_info['name'],
                    "evidence": relevant_alert.get('evidence', '') if relevant_alert else (
                        '; '.join(exploit_result['evidence']) if exploit_result and exploit_result['success'] else ''
                    ),
                    "cvss_score": cve_info['cvss'],
                    "risk_score": 4 if cve_info['cvss'] >= 9 else 3 if cve_info['cvss'] >= 7 else 2
                },
                "label": 0,  # TRUE_POSITIVE
                "label_name": "TRUE_POSITIVE",
                "label_source": "automated_exploit_cve" if exploit_result and exploit_result['success'] else "manual_verification_cve",
                "label_confidence": 1.0,
                "cve_id": cve_id,
                "cve_verified": True,
                "exploit_confirmed": exploit_result['success'] if exploit_result else False,
                "scanner_detected": scanner_detected,
                "exploit_tool": cve_info.get('exploit_repo', 'manual_testing'),
                "reproduction_date": datetime.now().strftime("%Y-%m-%d"),
                "moodle_version": "3.9.0",
                "attack_vector": cve_info['attack_vector'],
                "required_privilege": cve_info['required_privilege'],
                "notes": f"CVE {cve_id}: {cve_info['name']}. "
            }
            
            if exploit_result and exploit_result['success']:
                finding['notes'] += f"Automated exploit successful. Evidence: {', '.join(exploit_result['evidence'][:3])}. "
            
            if scanner_detected:
                finding['notes'] += f"Scanner detected with alert: {relevant_alert['alert']}."
            else:
                finding['notes'] += f"CRITICAL: Scanner missed this {cve_info['severity']} ({cve_info['cvss']} CVSS) vulnerability."
            
            return finding
            
        except Exception as e:
            self.print_error(f"Failed to extract finding: {e}")
            return None
    
    def add_to_dataset(self, finding: Dict) -> bool:
        """Add finding to training dataset"""
        # Find the latest processed findings file
        files = list(self.training_data_dir.glob("processed_findings_*.json"))
        
        if not files:
            self.print_error("No training data file found")
            return False
        
        latest_file = max(files, key=lambda p: p.stat().st_mtime)
        
        self.print_info(f"Adding to dataset: {latest_file}")
        
        try:
            # Backup first
            backup_file = latest_file.with_suffix(f'.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
            with open(latest_file, 'r') as f:
                data = json.load(f)
            
            with open(backup_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.print_info(f"Backup created: {backup_file}")
            
            # Add new finding
            data.append(finding)
            
            with open(latest_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.print_success(f"✅ Finding added! Total samples: {len(data)}")
            
            # Show new stats
            tp_count = sum(1 for f in data if f.get('label') == 0)
            fp_count = sum(1 for f in data if f.get('label') == 1)
            
            self.print_info(f"Current dataset: {tp_count} TP, {fp_count} FP")
            self.print_info(f"Imbalance ratio: {fp_count/tp_count:.1f}:1")
            
            return True
            
        except Exception as e:
            self.print_error(f"Failed to add to dataset: {e}")
            return False
    
    def update_cve_tracker(self, cve_id: str, status: str, scanner_detected: bool):
        """Update CVE tracker progress"""
        tracker = {}
        
        if self.cve_tracker_path.exists():
            with open(self.cve_tracker_path, 'r') as f:
                tracker = json.load(f)
        
        if 'cves' not in tracker:
            tracker['cves'] = {}
        
        tracker['cves'][cve_id] = {
            "status": status,
            "tested_date": datetime.now().isoformat(),
            "scanner_detected": scanner_detected,
            "cvss": self.CVE_DATABASE[cve_id]['cvss']
        }
        
        # Update summary
        completed = sum(1 for c in tracker['cves'].values() if c['status'] == 'completed')
        detected = sum(1 for c in tracker['cves'].values() if c.get('scanner_detected', False))
        
        tracker['summary'] = {
            "total_cves": len(self.CVE_DATABASE),
            "completed": completed,
            "scanner_detection_rate": f"{detected}/{completed}" if completed > 0 else "0/0",
            "last_updated": datetime.now().isoformat()
        }
        
        with open(self.cve_tracker_path, 'w') as f:
            json.dump(tracker, f, indent=2)
        
        self.print_success(f"CVE tracker updated: {completed}/{len(self.CVE_DATABASE)} completed")
    
    def update_progress_log(self, cve_id: str, finding: Dict):
        """Update progress log with CVE test results"""
        if not self.progress_log_path.exists():
            self.print_warning("Progress log not found")
            return
        
        entry = f"""
### {datetime.now().strftime("%Y-%m-%d %H:%M")} - {cve_id} Testing Completed

**CVE:** {cve_id} - {self.CVE_DATABASE[cve_id]['name']}  
**Severity:** {self.CVE_DATABASE[cve_id]['severity']} (CVSS {self.CVE_DATABASE[cve_id]['cvss']})  
**Exploit Result:** {'✅ Successful' if finding.get('exploit_confirmed') else '❌ Failed/Manual'}  
**Scanner Detection:** {'✅ Detected' if finding.get('scanner_detected') else '❌ Missed'}  
**Label:** TRUE_POSITIVE  
**Dataset Impact:** +1 TP sample  

**Notes:** {finding.get('notes', 'N/A')}

---
"""
        
        with open(self.progress_log_path, 'a', encoding='utf-8') as f:
            f.write(entry)
        
        self.print_success("Progress log updated")
    
    def test_cve(self, cve_id: str, target_url: str, username: str, password: str, 
                 skip_exploit: bool = False, skip_scan: bool = False) -> bool:
        """Complete CVE testing workflow"""
        
        if cve_id not in self.CVE_DATABASE:
            self.print_error(f"Unknown CVE: {cve_id}")
            return False
        
        cve_info = self.CVE_DATABASE[cve_id]
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Testing {cve_id}: {cve_info['name']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        exploit_result = None
        
        # Step 1: Run exploit if available
        if not skip_exploit and cve_info['exploit_repo']:
            if not self.clone_exploit(cve_id):
                self.print_warning("Continuing without automated exploit...")
            else:
                exploit_result = self.run_exploit(cve_id, target_url, username, password)
        
        # Step 2: Scan with ZAP
        scan_file = None
        if not skip_scan:
            scan_file = self.scan_with_zap(target_url, cve_id)
            if not scan_file:
                self.print_error("Scanner test failed")
                return False
        else:
            self.print_warning("Skipping scanner test")
        
        # Step 3: Extract finding
        if scan_file:
            finding = self.extract_finding(scan_file, cve_id, exploit_result)
            if not finding:
                self.print_error("Failed to extract finding")
                return False
            
            # Step 4: Add to dataset
            if self.add_to_dataset(finding):
                # Step 5: Update tracking
                self.update_cve_tracker(cve_id, "completed", finding['scanner_detected'])
                self.update_progress_log(cve_id, finding)
                
                print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}✅ CVE {cve_id} Testing Complete!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
                
                return True
        
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Automated CVE testing for MoodleSec ML training",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--cve', type=str, help='CVE ID to test (e.g., CVE-2021-36393)')
    parser.add_argument('--target', type=str, default='http://localhost:8080', 
                       help='Target Moodle URL (default: http://localhost:8080)')
    parser.add_argument('--username', type=str, default='admin', 
                       help='Moodle username (default: admin)')
    parser.add_argument('--password', type=str, default='Admin123!', 
                       help='Moodle password (default: Admin123!)')
    parser.add_argument('--list-cves', action='store_true', 
                       help='List all available CVEs')
    parser.add_argument('--skip-exploit', action='store_true', 
                       help='Skip exploit execution (scan only)')
    parser.add_argument('--skip-scan', action='store_true', 
                       help='Skip scanner test (exploit only)')
    parser.add_argument('--base-dir', type=str, default='.', 
                       help='Base directory (default: current directory)')
    
    args = parser.parse_args()
    
    tester = CVETester(base_dir=args.base_dir)
    
    if args.list_cves:
        tester.list_cves()
        return
    
    if not args.cve:
        parser.print_help()
        print(f"\n{Fore.YELLOW}Tip: Use --list-cves to see available CVEs{Style.RESET_ALL}")
        return
    
    success = tester.test_cve(
        args.cve, 
        args.target, 
        args.username, 
        args.password,
        skip_exploit=args.skip_exploit,
        skip_scan=args.skip_scan
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
