from flask import Flask, request, render_template_string, jsonify, send_file
import json
import ipaddress
import re
import os
from pyvis.network import Network

# --- CONFIGURATION (Direct I/O) ---
RIB_FILE = "/var/www/html/gobgp_rib.json"
RULES_FILE = "/var/www/html/arista_vrf_rules.json"
GRAPH_FILE = "/var/www/html/traffic_graph.html"
LISTEN_PORT = 5000

app = Flask(__name__)

# --- HTML TEMPLATE (Dark Mode & English) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BMP Analyzer | Direct Mode</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #3b82f6; }
        body { font-family: 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; display: flex; gap: 20px; height: 90vh; }
        .sidebar { width: 320px; background: var(--card); padding: 25px; border-radius: 16px; display: flex; flex-direction: column; }
        h1 { margin-top: 0; color: var(--accent); font-size: 1.6rem; }
        .badge { background: #334155; color: #94a3b8; padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; }
        label { display: block; margin-top: 15px; margin-bottom: 5px; font-size: 0.9rem; color: #cbd5e1; }
        input[type="text"] { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #334155; color: white; border-radius: 8px; box-sizing: border-box; font-family: monospace; }
        .btn { width: 100%; margin-top: 25px; padding: 14px; background: var(--accent); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; }
        .btn:hover { background: #2563eb; }
        .result-card { margin-top: 30px; padding: 15px; background: #0f172a; border-radius: 8px; border: 1px solid #334155; }
        .main-view { flex-grow: 1; background: var(--card); border-radius: 16px; padding: 10px; border: 1px solid #334155; }
        iframe { width: 100%; height: 100%; border: none; border-radius: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h1>🕸️ BMP Analyzer <span class="badge">Local</span></h1>
            <p style="color: #64748b; font-size: 0.85rem;">Direct I/O Visualizer</p>
            <form method="POST" action="/">
                <label>Source IP</label>
                <input type="text" name="src" value="{{ src_val }}" required placeholder="10.116.x.x">
                <label>Destination IP</label>
                <input type="text" name="dst" value="{{ dst_val }}" required placeholder="10.118.x.x">
                <button type="submit" class="btn">Analyze</button>
            </form>
            {% if result %}
            <div class="result-card">
                <p><strong>Status:</strong> <span style="color: #f59e0b;">{{ result.status }}</span></p>
                <p><strong>Source VRF:</strong> {{ result.source_vrf }}</p>
                <p><strong>Dest VRF:</strong> {{ result.dest_vrf }}</p>
                <hr style="border-color: #334155;">
                <p style="font-size: 0.8rem; color: #94a3b8;">{{ result.details }}</p>
            </div>
            {% endif %}
        </div>
        <div class="main-view">
            {% if graph_url %} <iframe src="{{ graph_url }}"></iframe> {% else %} 
            <div style="display:flex; justify-content:center; align-items:center; height:100%; color:#475569;"><h3>Waiting for Analysis...</h3></div> 
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

def load_json(filepath):
    if not os.path.exists(filepath): return None
    try:
        with open(filepath, 'r') as f: return json.load(f)
    except: return None

def normalize_rib(rib_data):
    routes = []
    if isinstance(rib_data, list): return rib_data
    if isinstance(rib_data, dict):
        for key, val in rib_data.items():
            pfx = re.search(r"prefix:([0-9./]+)", key)
            extracted = pfx.group(1) if pfx else None
            if isinstance(val, list):
                for r in val: r['_injected_prefix'] = extracted; routes.append(r)
            else: val['_injected_prefix'] = extracted; routes.append(val)
    return routes

def find_lpm(ip_input, rib):
    try:
        search = ipaddress.ip_address(ip_input)
    except: return None, None
    best_r = None; best_len = -1; matched_s = None
    for r in rib:
        pfx = r.get('_injected_prefix') or r.get('nlri', {}).get('prefix')
        if not pfx: continue
        try:
            rn = ipaddress.ip_network(pfx, strict=False)
            if search in rn and rn.prefixlen > best_len:
                best_len = rn.prefixlen; best_r = r; matched_s = str(rn)
        except: continue
    return best_r, matched_s

def get_vrf(route, rules):
    nlri = route.get('nlri', {})
    val = nlri.get('value', {})
    rd = val.get('rd', {}) or nlri.get('rd', {})
    rd_str = f"{rd.get('admin')}:{rd.get('assigned')}" if rd else None
    if rd_str:
        for v, c in rules.items():
            if c.get("rd") == rd_str: return v, rd_str
    return "Global", "N/A"

def analyze(src, dst, rules, rib):
    res = {"status": "UNKNOWN", "details": ""}
    flat_rib = normalize_rib(rib)
    src_r, src_sub = find_lpm(src, flat_rib)
    dst_r, dst_sub = find_lpm(dst, flat_rib)
    src_vrf, src_rd = get_vrf(src_r, rules) if src_r else ("Global", "N/A")
    dst_vrf, dst_rd = get_vrf(dst_r, rules) if dst_r else ("Global", "N/A")
    
    res.update({"source_vrf": src_vrf, "source_rd": src_rd, "matched_src": src_sub, "dest_vrf": dst_vrf, "dest_rd": dst_rd, "matched_dst": dst_sub})

    if not src_r or not dst_r:
        res["status"] = "FIREWALL_NO_ROUTE"; res["details"] = "Route not found -> Default Gateway -> Firewall."; return res
    if src_vrf == dst_vrf:
        res["status"] = "PERMIT_DIRECT"; res["details"] = "Intra-VRF Communication."; return res

    match = set(rules.get(src_vrf, {}).get("import_rts", [])) & set(rules.get(dst_vrf, {}).get("export_rts", []))
    if match:
        res["status"] = "PERMIT_LEAK"; res["details"] = f"Inter-VRF Allowed (RT: {list(match)})."; return res
    
    res["status"] = "FIREWALL_ISOLATION"; res["details"] = "VRF Isolation Active. Traffic routed to Firewall."; return res

def generate_graph(src_ip, dst_ip, res):
    net = Network(height="100%", width="100%", bgcolor="#1e293b", font_color="white", layout=True)
    net.add_node("SRC", label=f"Source\n{src_ip}", color="#10b981", shape="dot")
    net.add_node("V_SRC", label=f"VRF: {res['source_vrf']}", color="#f59e0b", shape="box", font={'face':'monospace', 'color':'white'})
    net.add_node("DST", label=f"Dest\n{dst_ip}", color="#10b981", shape="dot")
    
    net.add_edge("SRC", "V_SRC", color="white", width=2)

    if res['source_vrf'] != res['dest_vrf']:
        net.add_node("V_DST", label=f"VRF: {res['dest_vrf']}", color="#3b82f6", shape="box", font={'face':'monospace', 'color':'white'})
        
    if "FIREWALL" in res['status']:
        net.add_node("FW", label="🔥 FIREWALL", color="#ef4444", shape="diamond", size=30, font={'size':18, 'color':'white'})
        net.add_edge("V_SRC", "FW", color="#ef4444", width=3)
        if res['source_vrf'] != res['dest_vrf']:
            net.add_edge("FW", "V_DST", color="#ef4444", width=2, dashes=True)
            net.add_edge("V_DST", "DST", color="gray", width=1, dashes=True)
        else: net.add_edge("FW", "DST", dashes=True)
    elif res['source_vrf'] == res['dest_vrf']:
        net.add_edge("V_SRC", "DST", label="Direct", color="#10b981", width=3)
    else:
        net.add_edge("V_SRC", "V_DST", label="Leak", color="#f59e0b", width=3)
        net.add_edge("V_DST", "DST", color="white", width=2)

    net.set_options("""var options = { "layout": { "hierarchical": { "enabled": true, "direction": "LR", "sortMethod": "directed", "levelSeparation": 250 } }, "physics": { "enabled": false } }""")
    net.save_graph(GRAPH_FILE)

@app.route("/", methods=["GET", "POST"])
def index():
    res = None; graph_url = None
    s = request.form.get("src", ""); d = request.form.get("dst", "")
    if request.method == "POST":
        rules = load_json(RULES_FILE); rib = load_json(RIB_FILE)
        if rules and rib:
            res = analyze(s, d, rules, rib); generate_graph(s, d, res); graph_url = "/graph"
    return render_template_string(HTML_TEMPLATE, result=res, src_val=s, dst_val=d, graph_url=graph_url)

@app.route("/graph")
def serve_graph(): return send_file(GRAPH_FILE) if os.path.exists(GRAPH_FILE) else "Graph not found."

@app.route("/query")
def api_query():
    s = request.args.get("src"); d = request.args.get("dst")
    rules = load_json(RULES_FILE); rib = load_json(RIB_FILE)
    if not rules or not rib: return jsonify({"error": "Data missing"})
    return jsonify(analyze(s, d, rules, rib))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LISTEN_PORT)
