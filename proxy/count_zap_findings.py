#!/usr/bin/env python3
import json
import glob
import os

zap_dir = 'ml/training_data/real_data/OWASP_ZAP_Data'
files = glob.glob(os.path.join(zap_dir, '*.json'))
print(f'Found {len(files)} ZAP JSON files\n')

total_alerts = 0
total_instances = 0
alert_types = {}

for filepath in sorted(files):
    with open(filepath) as f:
        data = json.load(f)
        sites = data['site'] if isinstance(data['site'], list) else [data['site']]
        file_alerts = 0
        file_instances = 0
        for site in sites:
            if 'alerts' in site:
                for alert in site['alerts']:
                    file_alerts += 1
                    instances = alert.get('instances', [])
                    file_instances += len(instances)
                    alert_name = alert.get('name', 'Unknown')
                    alert_types[alert_name] = alert_types.get(alert_name, 0) + len(instances)
        
        total_alerts += file_alerts
        total_instances += file_instances
        filename = os.path.basename(filepath)
        print(f'{filename}: {file_alerts} alert types, {file_instances} instances')

print(f'\nTotal alert types: {total_alerts}')
print(f'Total findings (instances): {total_instances}')
print(f'\nTop 10 finding types:')
for name, count in sorted(alert_types.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f'  {name}: {count}')
