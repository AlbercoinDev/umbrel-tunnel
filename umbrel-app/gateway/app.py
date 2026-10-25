"""
tunnel-wg Gateway (Umbrel side)
- Auto-detects Umbrel services from exports.sh
- Manages HAProxy config for forwarding
- Web dashboard for configuration
"""
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

CONFIG_DIR = Path("/data/config")
WG_DIR = Path("/data/wireguard")
UMBREL_APP_DATA = Path("/umbrel-app-data")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
WG_DIR.mkdir(parents=True, exist_ok=True)

FORWARDS_FILE = CONFIG_DIR / "forwards.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"


def load_json(path, default=None):
    if path.exists():
        return json.loads(path.read_text())
    return default or []

def save_json(path, data):
    path.write_text(json.dumps(data, indent=2))

def load_forwards():
    return load_json(FORWARDS_FILE, [])

def save_forwards(forwards):
    save_json(FORWARDS_FILE, forwards)

def load_settings():
    return load_json(SETTINGS_FILE, {})

def save_settings(settings):
    save_json(SETTINGS_FILE, settings)


APP_PORT_MAP = {
    "bitcoin": {
        "services": [
            {"name": "Bitcoin P2P",  "container": "bitcoin_bitcoind_1",
             "ip_var": "APP_BITCOIN_NODE_IP", "port_var": "APP_BITCOIN_P2P_PORT", "default_port": 8333},
            {"name": "Bitcoin RPC",  "container": "bitcoin_bitcoind_1",
             "ip_var": "APP_BITCOIN_NODE_IP", "port_var": "APP_BITCOIN_RPC_PORT", "default_port": 8332},
            {"name": "Bitcoin UI",   "container": "bitcoin_app_1",
             "ip_var": "APP_BITCOIN_NODE_IP", "port_var": None, "default_port": 3000},
        ]
    },
    "electrs": {
        "services": [
            {"name": "Electrs (Electrum)", "container": "electrs_electrs_1",
             "ip_var": "APP_ELECTRS_NODE_IP", "port_var": "APP_ELECTRS_NODE_PORT", "default_port": 50001},
            {"name": "Electrs Web",         "container": "electrs_app_1",
             "ip_var": "APP_ELECTRS_IP", "port_var": None, "default_port": 3006},
        ]
    },
    "mempool": {
        "services": [
            {"name": "Mempool Web",  "container": "mempool_web_1",
             "ip_var": "APP_MEMPOOL_IP", "port_var": "APP_MEMPOOL_PORT", "default_port": 3006},
            {"name": "Mempool API",  "container": "mempool_api_1",
             "ip_var": "APP_MEMPOOL_API_IP", "port_var": None, "default_port": 8999},
        ]
    },
    "lightning": {
        "services": [
            {"name": "LND gRPC",  "container": "lightning_lnd_1",
             "ip_var": "APP_LIGHTNING_NODE_IP", "port_var": None, "default_port": 10009},
            {"name": "LND REST",  "container": "lightning_lnd_1",
             "ip_var": "APP_LIGHTNING_NODE_IP", "port_var": None, "default_port": 8080},
        ]
    },
}

def detect_services():
    detected = []
    exports_pattern = re.compile(
        r'export\s+(\w+)=["\']?(.*?)["\']?\s*(?:#|$)',
        re.MULTILINE)

    if not UMBREL_APP_DATA.exists():
        return detected

    try:
        app_dirs = sorted(UMBREL_APP_DATA.iterdir())
    except OSError:
        return detected

    for app_dir in app_dirs:
        if not app_dir.is_dir():
            continue
        exports_file = app_dir / "exports.sh"
        manifest_file = app_dir / "umbrel-app.yml"

        if not exports_file.exists():
            continue

        app_name = app_dir.name
        if manifest_file.exists():
            for line in manifest_file.read_text().splitlines():
                if line.startswith("name:"):
                    app_name = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break

        exports = {}
        for match in exports_pattern.finditer(exports_file.read_text()):
            exports[match.group(1)] = match.group(2)

        app_id = app_dir.name
        if app_id in APP_PORT_MAP:
            for svc in APP_PORT_MAP[app_id]["services"]:
                ip = exports.get(svc["ip_var"], "")
                port = svc["default_port"]
                if svc["port_var"] and svc["port_var"] in exports:
                    try:
                        port = int(exports[svc["port_var"]])
                    except ValueError:
                        pass

                if ip:
                    detected.append({
                        "id": f"{app_id}_{svc['container']}",
                        "app": app_name,
                        "name": svc["name"],
                        "container": svc["container"],
                        "ip": ip,
                        "port": port,
                    })

    return detected


def generate_haproxy_config(forwards):
    lines = [
        "global",
        "    daemon",
        "    stats socket /var/run/haproxy.sock mode 600",
        "",
        "defaults",
        "    mode tcp",
        "    timeout connect 5000ms",
        "    timeout client 50000ms",
        "    timeout server 50000ms",
        "",
    ]

    for i, fwd in enumerate(forwards):
        if not fwd.get("enabled", True):
            continue
        name = re.sub(r'[^a-zA-Z0-9_]', '_', fwd.get("name", f"svc_{i}"))
        lines += [
            f"frontend f_{name}",
            f"    bind {fwd.get('wg_ip', '10.0.0.2')}:{fwd['tun_port']}",
            f"    default_backend b_{name}",
            "",
            f"backend b_{name}",
            f"    server s_{name} {fwd['target_host']}:{fwd['target_port']}",
            "",
        ]

    return "\n".join(lines)

def reload_haproxy():
    forwards = load_forwards()
    config = generate_haproxy_config(forwards)
    HAPROXY_CFG.write_text(config)

    check = subprocess.run(
        ["haproxy", "-c", "-f", str(HAPROXY_CFG)],
        capture_output=True, text=True, timeout=10
    )
    if check.returncode != 0:
        print(f"[!] haproxy config invalid: {check.stderr}", flush=True)
        return

    pid_file = Path("/var/run/haproxy.pid")
    old_pid = ""
    if pid_file.exists():
        old_pid = pid_file.read_text().strip()

    try:
        cmd = ["haproxy", "-f", str(HAPROXY_CFG), "-p", str(pid_file)]
        if old_pid:
            cmd += ["-sf", old_pid]
        subprocess.run(cmd, check=False, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def ensure_policy_routing():
    """Route replies for tunnel-originated connections back via wg0."""
    wg_ip = get_wg_status().get("local_ip")
    if not wg_ip:
        return
    subprocess.run(
        ["ip", "route", "replace", "default", "via", "10.0.0.1",
         "dev", "wg0", "table", "200"],
        check=False, capture_output=True)
    rules = subprocess.run(
        ["ip", "rule", "show"], capture_output=True, text=True, timeout=5
    ).stdout
    if f"from {wg_ip} lookup 200" not in rules:
        subprocess.run(
            ["ip", "rule", "add", "from", wg_ip, "lookup", "200"],
            check=False, capture_output=True)


def get_wg_status():
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return {"connected": False, "error": "wg0 not found"}

        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return {"connected": False, "error": "no peers"}

        ip_result = subprocess.run(
            ["ip", "-4", "addr", "show", "wg0"],
            capture_output=True, text=True, timeout=5
        )
        local_ip = ""
        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
        if ip_match:
            local_ip = ip_match.group(1)

        peer_info = lines[1].split("\t")
        connected = len(peer_info) >= 5 and peer_info[4] != "0"

        return {
            "connected": connected,
            "local_ip": local_ip,
            "peer": peer_info[0] if len(peer_info) > 0 else "",
            "endpoint": peer_info[2] if len(peer_info) > 2 else "",
            "latest_handshake": peer_info[4] if len(peer_info) > 4 else "",
            "transfer_rx": peer_info[6] if len(peer_info) > 6 else "0",
            "transfer_tx": peer_info[7] if len(peer_info) > 7 else "0",
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}

def apply_wireguard_config(config_text):
    wg_conf = WG_DIR / "wg0.conf"
    wg_conf.write_text(config_text)
    Path("/etc/wireguard/wg0.conf").write_text(config_text)

    try:
        subprocess.run(["wg-quick", "down", "wg0"], check=False, timeout=10)
        subprocess.run(["wg-quick", "up", "/etc/wireguard/wg0.conf"],
                       check=True, timeout=10)
        ensure_policy_routing()
        return True, "WireGuard config applied"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to apply config: {e.stderr.decode() if e.stderr else 'unknown error'}"


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify({
        "wg": get_wg_status(),
        "forwards": len(load_forwards()),
        "services_detected": len(detect_services()),
    })

@app.route("/api/services")
def services():
    return jsonify(detect_services())

@app.route("/api/forwards", methods=["GET"])
def list_forwards():
    return jsonify(load_forwards())

@app.route("/api/forwards", methods=["POST"])
def create_forward():
    data = request.json
    if not data:
        return jsonify({"error": "no data"}), 400

    forwards = load_forwards()
    if any(f["tun_port"] == data["tun_port"] for f in forwards):
        return jsonify({"error": f"Port {data['tun_port']} already mapped"}), 400

    fwd = {
        "id": uuid.uuid4().hex[:8],
        "name": data.get("name", "unnamed"),
        "target_host": data.get("target_host", ""),
        "target_port": data.get("target_port", 0),
        "tun_port": data.get("tun_port", 0),
        "wg_ip": data.get("wg_ip", "10.0.0.2"),
        "enabled": data.get("enabled", True),
    }
    forwards.append(fwd)
    save_forwards(forwards)
    reload_haproxy()
    return jsonify(fwd)

@app.route("/api/forwards/<fwd_id>", methods=["DELETE"])
def delete_forward(fwd_id):
    forwards = load_forwards()
    forwards = [f for f in forwards if f["id"] != fwd_id]
    save_forwards(forwards)
    reload_haproxy()
    return jsonify({"ok": True})

@app.route("/api/forwards/<fwd_id>", methods=["PATCH"])
def update_forward(fwd_id):
    data = request.json
    forwards = load_forwards()
    for f in forwards:
        if f["id"] == fwd_id:
            for key in ["name", "target_host", "target_port", "tun_port", "enabled", "wg_ip"]:
                if key in data:
                    f[key] = data[key]
            save_forwards(forwards)
            reload_haproxy()
            return jsonify(f)
    return jsonify({"error": "not found"}), 404

@app.route("/api/wg-config", methods=["GET", "POST"])
def wg_config():
    if request.method == "POST":
        data = request.json
        if data and data.get("generate"):
            result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=5)
            privkey = result.stdout.strip()
            pub_result = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, timeout=5)
            pubkey = pub_result.stdout.strip()
            return jsonify({"pubkey": pubkey, "privkey": privkey})
        if not data or "config" not in data:
            return jsonify({"error": "no config provided"}), 400
        success, msg = apply_wireguard_config(data["config"])
        return jsonify({"ok": success, "message": msg})

    wg_conf = WG_DIR / "wg0.conf"
    if wg_conf.exists():
        return jsonify({"config": wg_conf.read_text()})
    return jsonify({"config": ""})

@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        data = request.json
        save_settings(data)
        return jsonify({"ok": True})
    return jsonify(load_settings())


if __name__ == "__main__":
    port = 8081
    debug = False
    args = iter(sys.argv[1:])
    for arg in args:
        if arg == "--port":
            port = int(next(args))
        if arg == "--debug":
            debug = True
    ensure_policy_routing()
    reload_haproxy()
    app.run(host="0.0.0.0", port=port, debug=debug)
