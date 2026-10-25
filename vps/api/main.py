import json, os, re, subprocess, uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="tunnel-wg-server")

CONFIG_DIR = Path(os.getenv("WG_CONFIG_DIR", "/wireguard-config"))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
FORWARDS_FILE = CONFIG_DIR / "forwards.json"
PEERS_FILE = CONFIG_DIR / "peers.json"
WG_CONF = CONFIG_DIR / "wg0.conf"

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


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

def load_peers():
    return load_json(PEERS_FILE, [])

def save_peers(peers):
    save_json(PEERS_FILE, peers)


DNAT_CHAIN = "TUNNEL-DNAT"
FWD_CHAIN = "TUNNEL-FWD"

def ensure_iptables_chains():
    subprocess.run(["iptables", "-t", "nat", "-N", DNAT_CHAIN], check=False,
                   capture_output=True)
    subprocess.run(["iptables", "-N", FWD_CHAIN], check=False, capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", DNAT_CHAIN],
                   check=False, capture_output=True) or subprocess.run(
        ["iptables", "-t", "nat", "-I", "PREROUTING", "-j", DNAT_CHAIN],
        check=False, capture_output=True)
    subprocess.run(["iptables", "-C", "FORWARD", "-j", FWD_CHAIN],
                   check=False, capture_output=True) or subprocess.run(
        ["iptables", "-I", "FORWARD", "-j", FWD_CHAIN],
        check=False, capture_output=True)

def apply_iptables():
    ensure_iptables_chains()
    subprocess.run(["iptables", "-t", "nat", "-F", DNAT_CHAIN], check=False, capture_output=True)
    subprocess.run(["iptables", "-F", FWD_CHAIN], check=False, capture_output=True)

    subprocess.run(
        ["iptables", "-A", FWD_CHAIN, "-m", "conntrack", "--ctstate",
         "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=False, capture_output=True)
    subprocess.run(
        ["iptables", "-A", FWD_CHAIN, "-i", "wg0", "-j", "ACCEPT"],
        check=False, capture_output=True)

    for fwd in load_forwards():
        if not fwd.get("enabled", True):
            continue
        target = f"{fwd['target_ip']}:{fwd['target_port']}"
        subprocess.run(
            ["iptables", "-t", "nat", "-A", DNAT_CHAIN,
             "-p", "tcp", "--dport", str(fwd["dport"]),
             "-j", "DNAT", "--to-destination", target],
            check=False, capture_output=True)
        subprocess.run(
            ["iptables", "-A", FWD_CHAIN,
             "-p", "tcp", "-d", fwd["target_ip"],
             "--dport", str(fwd["dport"]), "-j", "ACCEPT"],
            check=False, capture_output=True)


def generate_wg_server_config(peers):
    privkey = (CONFIG_DIR / "server_privatekey").read_text().strip() if (CONFIG_DIR / "server_privatekey").exists() else ""
    if not privkey:
        result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=5)
        privkey = result.stdout.strip()
        (CONFIG_DIR / "server_privatekey").write_text(privkey)
        pub_result = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, timeout=5)
        (CONFIG_DIR / "server_publickey").write_text(pub_result.stdout.strip())

    config = f"""[Interface]
Address = 10.0.0.1/24
PrivateKey = {privkey}
ListenPort = 51820
SaveConfig = false

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT

"""
    for peer in peers:
        config += f"""
[Peer]
# {peer.get('name', 'unnamed')}
PublicKey = {peer['public_key']}
AllowedIPs = {peer['allowed_ip']}/32
"""
        if peer.get("endpoint"):
            config += f"Endpoint = {peer['endpoint']}\n"
    return config

def wg_interface_up():
    result = subprocess.run(["wg", "show", "wg0"], capture_output=True, text=True, timeout=5)
    return result.returncode == 0

def reload_wireguard():
    peers = load_peers()
    WG_CONF.write_text(generate_wg_server_config(peers))
    if not wg_interface_up():
        subprocess.run(["wg-quick", "up", str(WG_CONF)], check=False, capture_output=True)
    subprocess.run(["wg", "syncconf", "wg0", str(WG_CONF)], check=False)


class PeerCreate(BaseModel):
    name: str
    public_key: str
    allowed_ip: str = "10.0.0.2"
    endpoint: str = ""

class ForwardCreate(BaseModel):
    name: str
    dport: int
    target_ip: str
    target_port: int
    auth_mode: str = "none"
    enabled: bool = True

class ForwardUpdate(BaseModel):
    name: str | None = None
    auth_mode: str | None = None
    enabled: bool | None = None


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "peers": load_peers(),
        "forwards": load_forwards(),
    })

@app.get("/api/peers")
async def list_peers():
    return load_peers()

@app.post("/api/peers")
async def create_peer(peer: PeerCreate):
    peers = load_peers()
    if any(p["public_key"] == peer.public_key for p in peers):
        raise HTTPException(400, "Peer already exists")
    new_peer = peer.model_dump()
    new_peer["id"] = str(uuid.uuid4())[:8]
    peers.append(new_peer)
    save_peers(peers)
    reload_wireguard()
    apply_iptables()
    return new_peer

@app.delete("/api/peers/{peer_id}")
async def delete_peer(peer_id: str):
    peers = load_peers()
    peers = [p for p in peers if p["id"] != peer_id]
    save_peers(peers)
    reload_wireguard()
    apply_iptables()
    return {"ok": True}

@app.get("/api/forwards")
async def list_forwards():
    return load_forwards()

@app.post("/api/forwards")
async def create_forward(fwd: ForwardCreate):
    forwards = load_forwards()
    if any(f["dport"] == fwd.dport for f in forwards):
        raise HTTPException(400, f"Port {fwd.dport} already forwarded")
    new_fwd = fwd.model_dump()
    new_fwd["id"] = str(uuid.uuid4())[:8]
    forwards.append(new_fwd)
    save_forwards(forwards)
    apply_iptables()
    return new_fwd

@app.delete("/api/forwards/{fwd_id}")
async def delete_forward(fwd_id: str):
    forwards = load_forwards()
    forwards = [f for f in forwards if f["id"] != fwd_id]
    save_forwards(forwards)
    apply_iptables()
    return {"ok": True}

@app.patch("/api/forwards/{fwd_id}")
async def update_forward(fwd_id: str, update: ForwardUpdate):
    forwards = load_forwards()
    for f in forwards:
        if f["id"] == fwd_id:
            if update.name is not None:
                f["name"] = update.name
            if update.auth_mode is not None:
                f["auth_mode"] = update.auth_mode
            if update.enabled is not None:
                f["enabled"] = update.enabled
            save_forwards(forwards)
            apply_iptables()
            return f
    raise HTTPException(404, "Forward not found")

@app.get("/api/status")
async def system_status():
    wg_status = subprocess.run(
        ["wg", "show", "wg0", "dump"],
        capture_output=True, text=True, timeout=5
    )
    peers_connected = 0
    if wg_status.returncode == 0:
        lines = wg_status.stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) >= 5 and parts[4] != "0":
                    peers_connected += 1

    return {
        "peers_total": len(load_peers()),
        "peers_connected": peers_connected,
        "forwards_total": len(load_forwards()),
        "wg_running": wg_status.returncode == 0,
    }

@app.get("/api/peers/{peer_id}/config")
async def get_peer_config(peer_id: str):
    peers = load_peers()
    peer = next((p for p in peers if p["id"] == peer_id), None)
    if not peer:
        raise HTTPException(404, "Peer not found")

    server_pub = (CONFIG_DIR / "server_publickey").read_text().strip() if (CONFIG_DIR / "server_publickey").exists() else ""
    if not server_pub:
        raise HTTPException(500, "Server not initialized")

    vps_ip = os.environ.get("VPS_PUBLIC_IP", "")
    if not vps_ip:
        try:
            result = subprocess.run(
                ["curl", "-s", "https://api.ipify.org"],
                capture_output=True, text=True, timeout=10
            )
            vps_ip = result.stdout.strip()
        except:
            vps_ip = "CHANGE_ME"

    config = f"""[Interface]
PrivateKey = <UMBREL_PRIVATE_KEY>
Address = {peer['allowed_ip']}/24

[Peer]
PublicKey = {server_pub}
Endpoint = {vps_ip}:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
"""
    return JSONResponse({"config": config, "qr": config})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("API_PORT", "8080")))
