import re
import json
from netmiko import ConnectHandler

# --- AYARLAR ---
LEAF_DEVICE = {
    'device_type': 'arista_eos',
    'host':   '192.168.122.11',  # Leaf Switch IP Adresi
    'username': 'admin',         # Kullanici Adi
    'password': 'password',      # Sifre
    'secret': 'password',        # Enable Sifresi (Varsa)
}

OUTPUT_FILE = "arista_vrf_rules.json" # GoBGP dizinine veya scriptin yanina kaydedin

def get_vrf_config():
    """ Arista cihazina baglanir ve VRF configini ham metin olarak alir. """
    print(f"Leaf cihazina baglaniliyor: {LEAF_DEVICE['host']}...")
    try:
        net_connect = ConnectHandler(**LEAF_DEVICE)
        net_connect.enable()
        # Sadece VRF tanimlarini getir
        output = net_connect.send_command("show running-config section vrf")
        net_connect.disconnect()
        return output
    except Exception as e:
        print(f"[HATA] Baglanti saglanamadi: {e}")
        return None

def parse_vrf_config(config_text):
    """ Ham metni analiz edip Dictionary yapisina cevirir. """
    rules = {}
    current_vrf = None
    
    # Satir satir oku
    for line in config_text.splitlines():
        line = line.strip()
        
        # 1. VRF Ismini Yakala
        # Ornek: "vrf instance PROVIDER"
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

        # 2. RD (Route Distinguisher) Yakala
        # Ornek: "rd 10.32.113.12:240"
        rd_match = re.match(r"^rd (\S+)", line)
        if rd_match:
            rules[current_vrf]["rd"] = rd_match.group(1)
        
        # 3. Route Target (RT) Yakala
        # Ornekler:
        # route-target import evpn 65000:240
        # route-target export evpn 65000:240
        # route-target both 65000:999
        if "route-target" in line:
            # RT degerini bul (genelde : iceren kisim)
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
        
        # JSON Olarak Kaydet
        try:
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(parsed_data, f, indent=4)
            print(f"Basarili! VRF kurallari '{OUTPUT_FILE}' dosyasina kaydedildi.")
            print(f"Toplam {len(parsed_data)} VRF islendi.")
        except IOError as e:
            print(f"[HATA] Dosya yazilamadi: {e}")

if __name__ == "__main__":
    main()
