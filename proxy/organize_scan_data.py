#!/usr/bin/env python3
"""
Data Organization Script
Organize scan results from different sources into structured folders
"""

import os
import json
import shutil
from datetime import datetime
from pathlib import Path

class DataOrganizer:
    def __init__(self, base_dir='data'):
        """Initialize data organizer"""
        self.base_dir = Path(base_dir)
        self.setup_directories()
    
    def setup_directories(self):
        """Create directory structure"""
        directories = [
            'raw/acunetix',
            'raw/owasp_zap',
            'raw/other',
            'processed',
            'merged',
            'backup'
        ]
        
        for directory in directories:
            path = self.base_dir / directory
            path.mkdir(parents=True, exist_ok=True)
            print(f'[+] Created: {path}')
    
    def detect_scanner_type(self, json_file):
        """Detect which scanner produced the JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check for Acunetix format
            if 'export' in data and 'scans' in data['export']:
                scan_info = data['export']['scans'][0].get('info', {})
                
                # Check scanner identifier
                if 'build' in scan_info:
                    build = scan_info['build']
                    if 'acunetix' in build.lower() or build.startswith('24.'):
                        return 'acunetix'
                    elif 'zap' in build.lower():
                        return 'owasp_zap'
                
                # Check source_type
                source_type = scan_info.get('source_type', '')
                if 'zap' in source_type.lower():
                    return 'owasp_zap'
                elif 'acunetix' in source_type.lower():
                    return 'acunetix'
                
                # Check scanner field
                scanner = scan_info.get('scanner', '')
                if 'zap' in scanner.lower():
                    return 'owasp_zap'
                elif 'acunetix' in scanner.lower():
                    return 'acunetix'
            
            return 'other'
        
        except Exception as e:
            print(f'[!] Error detecting scanner type: {e}')
            return 'other'
    
    def organize_file(self, json_file, scanner_type=None):
        """Move JSON file to appropriate directory"""
        json_path = Path(json_file)
        
        if not json_path.exists():
            print(f'[!] File not found: {json_file}')
            return False
        
        # Auto-detect scanner type if not provided
        if scanner_type is None:
            scanner_type = self.detect_scanner_type(json_file)
        
        # Determine destination
        dest_dir = self.base_dir / 'raw' / scanner_type
        dest_file = dest_dir / json_path.name
        
        # Backup if file exists
        if dest_file.exists():
            backup_dir = self.base_dir / 'backup'
            backup_file = backup_dir / f"{json_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            shutil.copy2(dest_file, backup_file)
            print(f'[*] Backed up existing file to: {backup_file}')
        
        # Move file
        shutil.copy2(json_path, dest_file)
        print(f'[+] Organized: {json_path.name} → {dest_dir}')
        
        return True
    
    def organize_all(self, source_dir='.'):
        """Organize all JSON files in a directory"""
        source_path = Path(source_dir)
        json_files = list(source_path.glob('*.json'))
        
        if not json_files:
            print(f'[!] No JSON files found in {source_dir}')
            return
        
        print(f'\n[*] Found {len(json_files)} JSON files')
        print(f'[*] Organizing files...\n')
        
        stats = {'acunetix': 0, 'owasp_zap': 0, 'other': 0}
        
        for json_file in json_files:
            scanner_type = self.detect_scanner_type(json_file)
            if self.organize_file(json_file, scanner_type):
                stats[scanner_type] += 1
        
        # Print summary
        print(f'\n{"="*60}')
        print(f'[+] Organization Summary:')
        print(f'    Acunetix files: {stats["acunetix"]}')
        print(f'    OWASP ZAP files: {stats["owasp_zap"]}')
        print(f'    Other files: {stats["other"]}')
        print(f'    Total: {sum(stats.values())}')
        print(f'{"="*60}\n')
    
    def count_findings(self):
        """Count total findings in all organized files"""
        print(f'\n[*] Counting findings...\n')
        
        total_findings = 0
        scanner_stats = {}
        
        for scanner_type in ['acunetix', 'owasp_zap', 'other']:
            scanner_dir = self.base_dir / 'raw' / scanner_type
            json_files = list(scanner_dir.glob('*.json'))
            
            scanner_findings = 0
            
            for json_file in json_files:
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    if 'export' in data and 'scans' in data['export']:
                        for scan in data['export']['scans']:
                            vuln_types = scan.get('vulnerability_types', [])
                            scanner_findings += len(vuln_types)
                
                except Exception as e:
                    print(f'[!] Error reading {json_file}: {e}')
            
            scanner_stats[scanner_type] = scanner_findings
            total_findings += scanner_findings
        
        # Print statistics
        print(f'{"="*60}')
        print(f'[+] Findings Statistics:')
        print(f'    Acunetix: {scanner_stats["acunetix"]} findings')
        print(f'    OWASP ZAP: {scanner_stats["owasp_zap"]} findings')
        print(f'    Other: {scanner_stats["other"]} findings')
        print(f'    Total: {total_findings} findings')
        print(f'{"="*60}\n')
        
        # Check if sufficient for ML training
        if total_findings >= 500:
            print('[+] ✓ Sufficient data for ML training (500+ findings)')
        elif total_findings >= 200:
            print('[*] ⚠ Minimum data for ML training (200+ findings)')
        else:
            print(f'[!] ✗ Insufficient data. Need {200 - total_findings} more findings')
        
        return total_findings, scanner_stats
    
    def generate_report(self):
        """Generate data collection report"""
        print(f'\n{"="*60}')
        print(f'DATA COLLECTION REPORT')
        print(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        print(f'{"="*60}\n')
        
        # Count files
        acunetix_files = len(list((self.base_dir / 'raw/acunetix').glob('*.json')))
        zap_files = len(list((self.base_dir / 'raw/owasp_zap').glob('*.json')))
        other_files = len(list((self.base_dir / 'raw/other').glob('*.json')))
        
        print(f'[*] Files Collected:')
        print(f'    Acunetix: {acunetix_files} files')
        print(f'    OWASP ZAP: {zap_files} files')
        print(f'    Other: {other_files} files')
        print(f'    Total: {acunetix_files + zap_files + other_files} files\n')
        
        # Count findings
        total_findings, scanner_stats = self.count_findings()
        
        # Recommendations
        print(f'\n[*] Recommendations:')
        
        if total_findings < 200:
            print(f'    → Scan {(200 - total_findings) // 30 + 1} more websites with OWASP ZAP')
        elif total_findings < 500:
            print(f'    → Scan {(500 - total_findings) // 30 + 1} more websites for better ML accuracy')
        else:
            print(f'    → ✓ Ready for ML training!')
            print(f'    → Next steps:')
            print(f'       1. python import_acunetix_data.py')
            print(f'       2. python merge_training_data.py')
            print(f'       3. python retrain_models.py')


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Organize scan data')
    parser.add_argument('--source', default='data', help='Source directory with JSON files')
    parser.add_argument('--organize', action='store_true', help='Organize files')
    parser.add_argument('--count', action='store_true', help='Count findings')
    parser.add_argument('--report', action='store_true', help='Generate report')
    
    args = parser.parse_args()
    
    # Initialize organizer
    organizer = DataOrganizer()
    
    # Execute requested actions
    if args.organize:
        organizer.organize_all(args.source)
    
    if args.count:
        organizer.count_findings()
    
    if args.report or (not args.organize and not args.count):
        organizer.generate_report()


if __name__ == '__main__':
    main()
