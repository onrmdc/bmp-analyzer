import http.server
import socketserver
import json
import urllib.request
import urllib.parse
import ipaddress
import sys
import re

# --- KONFIGURASYON ---
# JSON verilerinin bulundugu URL
DATA_SOURCE_URL = "http://192.168.122.181:8000"
LISTEN_PORT = 5000

def fetch_json(endpoint):
    url = f"{DATA_SOURCE_URL}/{endpoint}"
    try:
        with urllib.request.urlopen(url) as response:
            if response.getcode() == 200:
                data = response.read()
                return json.loads(data)
    except Exception as e:
        print(f"[HATA] Veri cekilemedi ({url}): {e}")
        return None

def normalize_rib(rib_data):
    """ GoBGP JSON yapisindaki key string'den prefix bilgisini ayiklar. """
    routes = []
    if isinstance(rib_data, list): return rib_data
    if isinstance(rib_data, dict):
        for key_str, path_list in rib_data.items():
            extracted_prefix = None
            match = re.search(r"prefix:([0-9./]+)", key_str)
            if match: extracted_prefix = match.group(1)
            
            if isinstance(path_list, list):
                for route in path_list:
                    route['_injected_prefix'] = extracted_prefix
                    routes.append(route)
            else:
                path_list['_injected_prefix'] = extracted_prefix
                routes.append(path_list)
    return routes

def get_rd_from_route(route):
    """ Rotanin RD (Route Distinguisher) degerini döner. """
    nlri = route.get('nlri', {})
    val = nlri.get('value', {})
    rd_obj = val.get('rd', {})
    if not rd_obj and 'rd' in nlri: rd_obj = nlri['rd']
    if rd_obj:
        admin = rd_obj.get('admin')
        assigned = rd_obj.get('assigned')
        if admin is not None and assigned is not None:
            return f"{admin}:{assigned}"
    return None

def extract_prefix_from_route(route):
    if route.get('_injected_prefix'): return route['_injected_prefix']
    nlri = route.get('nlri', {})
    if 'prefix' in nlri: return nlri['prefix']
    if 'value' in nlri:
        val = nlri['value']
        if 'prefix' in val: return val['prefix']
        if 'ip' in val: return val['ip']
    return None

def find_longest_match(input_str, flat_rib):
    """
    Kullanici girdisini (IP veya Subnet) kapsayan en spesifik rotayi bulur.
    Strict Subnet kurali uygular: /16 sorgusu /24 rotasiyla eslesmez.
    """
    search_obj = None
    is_subnet_search = False
    
    try:
        if '/' in input_str:
            search_obj = ipaddress.ip_network(input_str, strict=False)
            is_subnet_search = True
        else:
            search_obj = ipaddress.ip_address(input_str)
    except ValueError:
        return None, None

    best_route = None
    best_prefix_len = -1
    matched_subnet = None
    
    for route in flat_rib:
        prefix_str = extract_prefix_from_route(route)
        if not prefix_str: continue
        
        try:
            if '/' not in prefix_str:
                route_network = ipaddress.ip_network(f"{prefix_str}/32", strict=False)
            else:
                route_network = ipaddress.ip_network(prefix_str, strict=False)
            
            is_match = False
            
            if is_subnet_search:
                # Aranan subnet, rotanin icine TAM SIGMALI
                if (search_obj.network_address in route_network and 
                    search_obj.prefixlen >= route_network.prefixlen):
                    is_match = True
            else:
                if search_obj in route_network:
                    is_match = True

            if is_match:
                if route_network.prefixlen > best_prefix_len:
                    best_prefix_len = route_network.prefixlen
                    best_route = route
                    matched_subnet = str(route_network)
        except ValueError: continue
            
    return best_route, matched_subnet

def identify_vrf(route, rules):
    """ RD degerine gore VRF ismini cozer. """
    route_rd = get_rd_from_route(route)
    if route_rd:
        for vrf, config in rules.items():
            if config.get("rd") == route_rd: return vrf
    return "Unknown_VRF"

def analyze_traffic(src_input, dst_input, rules, rib):
    result = {
        "query_src": src_input,
        "query_dst": dst_input,
        "source_route": None,
        "dest_route": None,
        "source_vrf": None,
        "dest_vrf": None,
        "status": "UNKNOWN",
        "details": ""
    }

    flat_rib = normalize_rib(rib)

    # 1. Rota Taramasi
    src_route, src_subnet = find_longest_match(src_input, flat_rib)
    dst_route, dst_subnet = find_longest_match(dst_input, flat_rib)

    # 2. Rota Bulunamadiysa -> Default Gateway (Firewall)
    if not src_route or not dst_route:
        result["source_route"] = src_subnet if src_subnet else "0.0.0.0/0 (Default)"
        result["dest_route"] = dst_subnet if dst_subnet else "0.0.0.0/0 (Default)"
        result["source_vrf"] = identify_vrf(src_route, rules) if src_route else "Global/Default"
        result["dest_vrf"] = identify_vrf(dst_route, rules) if dst_route else "Global/Default"
        
        result["status"] = "FIREWALL_KONTROLU"
        result["details"] = "Spesifik BGP rotasi yok. Trafik Default Gateway (Firewall) uzerinden akar."
        return result
    
    # 3. VRF Analizi
    result["source_route"] = src_subnet
    result["dest_route"] = dst_subnet
    src_vrf = identify_vrf(src_route, rules)
    result["source_vrf"] = src_vrf
    dst_vrf = identify_vrf(dst_route, rules)
    result["dest_vrf"] = dst_vrf

    if src_vrf == "Unknown_VRF" or dst_vrf == "Unknown_VRF":
        result["status"] = "BELIRSIZ"
        result["details"] = "VRF tespiti yapilamadi (RD eslesmedi)."
        return result

    # 4. Izin Kontrolu
    if src_vrf == dst_vrf:
        result["status"] = "IZINLI_DIRECT"
        result["details"] = f"Intra-VRF. Ayni VRF ({src_vrf}) icinde dogrudan iletisim."
        return result

    src_config = rules.get(src_vrf, {})
    dst_config = rules.get(dst_vrf, {})
    
    match = set(src_config.get("import_rts", [])) & set(dst_config.get("export_rts", []))
    
    if match:
        result["status"] = "IZINLI_DIRECT"
        result["details"] = f"Inter-VRF Izinli. {src_vrf} -> {dst_vrf} (RT: {list(match)})."
    else:
        result["status"] = "FIREWALL_KONTROLU"
        result["details"] = f"Izolasyon (BGP Import yok). Trafik Default Gateway (Firewall) uzerinden akar."

    return result

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/query':
            try:
                qs = urllib.parse.parse_qs(parsed.query)
                src = qs.get('src', [None])[0]
                dst = qs.get('dst', [None])[0]
                
                if not src or not dst:
                    self.send_response(400); self.wfile.write(b"Eksik parametre."); return

                rules = fetch_json("arista_vrf_rules.json")
                rib = fetch_json("gobgp_rib.json")
                
                if rules and rib:
                    res = analyze_traffic(src, dst, rules, rib)
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(res, indent=4).encode('utf-8'))
                else:
                    self.send_response(500); self.wfile.write(b"Veri hatasi")
            except Exception as e:
                 self.send_response(500); self.wfile.write(f"Sunucu Hatasi: {e}".encode('utf-8'))
        else:
            self.send_response(404)

if __name__ == '__main__':
    print(f"BMP Analyzer Baslatildi: Port {LISTEN_PORT}")
    server = socketserver.TCPServer(("", LISTEN_PORT), RequestHandler)
    server.serve_forever()
