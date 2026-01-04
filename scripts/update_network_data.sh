#!/bin/bash

# 1. Fetch BGP RIB from GoBGP
echo "Fetching BGP RIB..."
/usr/local/bin/gobgp global rib -j > /var/www/html/gobgp_rib.json

# 2. Fetch VRF Config from Leaf Switch (via SSH)
echo "Fetching VRF Config from Leaf..."
/usr/bin/python3 /root/codes/collect_leaf.py

# 3. Set Permissions for Flask App
chmod 644 /var/www/html/*.json

echo "Network Data Updated."
