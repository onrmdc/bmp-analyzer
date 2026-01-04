#!/bin/bash
# Fetch GoBGP RIB table as JSON
/usr/local/bin/gobgp global rib -j > /var/www/html/gobgp_rib.json

# If VRF Rules file does not exist, create a dummy one (for testing)
if [ ! -f "/var/www/html/arista_vrf_rules.json" ]; then
    echo '{
        "PROVIDER": {"rd": "10.32.113.12:240", "import_rts": ["65000:240"], "export_rts": ["65000:240"]},
        "STAGE": {"rd": "10.32.113.12:241", "import_rts": ["65000:241"], "export_rts": ["65000:241"]}
    }' > /var/www/html/arista_vrf_rules.json
fi

chmod 644 /var/www/html/*.json
