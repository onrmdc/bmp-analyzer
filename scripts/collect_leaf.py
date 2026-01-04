import re
import json
import os
from netmiko import ConnectHandler

# --- CONFIGURATION ---
# In a real scenario, use Environment Variables for security
LEAF_DEVICE = {
    'device_type': 'arista_eos',
    'host':   '192.168.122.11',  # Leaf Switch IP
    'username': 'admin',
    'password': 'password',
    'secret': 'password',
}

# Save directly to the web directory for Direct I/O access
OUTPUT_FILE = "/var/www/html/arista_vrf_rules.json"

def get_vrf_config():
    """ Connects to Arista device via SSH and fetches VRF config section. """
    print(f"Connecting to Leaf: {LEAF_DEVICE['host']}...")
    try:
        net_connect = ConnectHandler(**LEAF_DEVICE)
        net_connect.enable()
        # Fetch only VRF definitions
        output = net_connect.send_command("show running-config section vrf")
        net_connect.disconnect()
        return output
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return None

def parse_vrf_config(config_text):
    """ Parses raw Arista config into a Dictionary. """
    rules = {}
    current_vrf = None
    
    for line in config_text.splitlines():
        line = line.strip()
        
        # 1. Match VRF Name
        vrf_match = re.match(r"^vrf instance (\S+)", line)
        if vrf_match:
            current_vrf = vrf_match.group(1)
            rules[current_vrf] = {
                "rd": None, 
                "import_rts": [], 
                "export_rts": []
            }
            continue

        if not current_vrf:
            continue

        # 2. Match RD (Route Distinguisher)
        rd_match = re.match(r"^rd (\S+)", line)
        if rd_match:
            rules[current_vrf]["rd"] = rd_match.group(1)
        
        # 3. Match Route Targets (RT)
        if "route-target" in line:
            rt_val_match = re.search(r"(\d+:\d+)", line)
            if rt_val_match:
                rt_val = rt_val_match.group(1)
                
                if "import" in line:
                    rules[current_vrf]["import_rts"].append(rt_val)
                elif "export" in line:
                    rules[current_vrf]["export_rts"].append(rt_val)
                elif "both" in line:
                    rules[current_vrf]["import_rts"].append(rt_val)
                    rules[current_vrf]["export_rts"].append(rt_val)

    return rules

def main():
    config_text = get_vrf_config()
    
    if config_text:
        parsed_data = parse_vrf_config(config_text)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

        try:
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(parsed_data, f, indent=4)
            print(f"Success! VRF rules saved to '{OUTPUT_FILE}'.")
            print(f"Total VRFs processed: {len(parsed_data)}")
        except IOError as e:
            print(f"[ERROR] Could not write file: {e}")

if __name__ == "__main__":
    main()
