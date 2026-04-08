#!/bin/bash
CONTAINER=$1

echo "✅ Restoring $CONTAINER to IoT network..."
docker network disconnect quarantine-lan $CONTAINER
docker network connect iot-lan $CONTAINER

# Reset quarantined flag in device_history.json
python3 -c "
import json, sys, os
name = '$1'
try:
    with open(os.environ.get('DEVICE_HISTORY', '/home/sk/device_history.json')) as f:
        h = json.load(f)
    if name in h:
        h[name]['quarantined']   = False
        h[name]['under_attack']  = False
        with open('/home/sk/device_history.json', 'w') as f:
            json.dump(h, f, indent=2)
        print(f'History reset for {name}')
except Exception as e:
    print(f'History reset skipped: {e}')
" 2>/dev/null



echo "✅ $CONTAINER restored to IoT network (192.168.20.0/24)"



nft flush chain ip raw PREROUTING
echo "✅ nftables raw rules flushed"
