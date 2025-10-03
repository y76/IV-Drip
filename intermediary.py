# intermediary.py
# Intermediary: accepts both Broker and Client connections and relays per §5.
# Start this first:  python intermediary.py
import socket, threading, json, random, os, time
from typing import Dict, Any
from my_afgh06 import ReEnc, Add, Blind, charm_microbench  # toy ops + optional bench

HOST = "127.0.0.1"
PORT = 50500
DEBUG = os.getenv("DEBUG", "0") == "1"
DO_CHARMBENCH = os.getenv("CHARM_BENCH", "0") == "1"

# State
broker_conn = None
broker_addr = None
broker_profile = {}
broker_schema = []

client_conn = None
client_addr = None
client_profile = {}
client_ciphertexts = {}
client_rekeys = {}

metrics = {
    "client_to_I_bytes": 0,
    "I_to_broker_bytes": 0,
    "broker_to_I_bytes": 0,
    "I_to_client_bytes": 0,
    "t_lookup": 0.0,
    "t_enc1": 0.0,
    "t_match": 0.0
}

def _send(sock, msg: Dict[str,Any]) -> bytes:
    b = json.dumps(msg).encode("utf-8")
    sock.sendall(b + b"\n")
    return b

def send_metered(sock, msg: Dict[str,Any], meter_key: str):
    b = _send(sock, msg)
    if meter_key in metrics:
        metrics[meter_key] += len(b)

def recv_metered(sock, meter_key: str) -> Dict[str,Any]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    if meter_key in metrics:
        metrics[meter_key] += len(data)
    return json.loads(data.decode("utf-8"))

def handle_client(sock, addr):
    global client_conn, client_addr, client_profile, client_ciphertexts, client_rekeys
    client_conn, client_addr = sock, addr
    req = recv_metered(sock, "client_to_I_bytes")
    if req.get("type") != "REQUEST":
        return
    client_profile = {
        "IDC": req["IDC"],
        "request_type": req["request_type"],  # "Delete", "Access", "Opt-out"
        "pk": req["pk"]
    }
    client_ciphertexts = req["ciphertexts"]     # Enc2(-x_i)
    client_rekeys = req["rekeys"]               # rk_{C->B}
    send_metered(sock, {"type":"ACK","msg":"request stored"}, "I_to_client_bytes")
    if broker_conn is not None:
        run_pivot()

def handle_broker(sock, addr):
    global broker_conn, broker_addr, broker_profile, broker_schema
    broker_conn, broker_addr = sock, addr
    hello = recv_metered(sock, "broker_to_I_bytes")
    if hello.get("type") != "REGISTER":
        return
    broker_profile = hello["broker"]
    broker_schema = list(broker_profile["dataset"].keys())
    send_metered(sock, {"type":"ACK","msg":"registered"}, "I_to_broker_bytes")
    if client_conn is not None:
        run_pivot()

def run_pivot():
    # ---- Phase 2(1): LOOKUP ----
    t0 = time.perf_counter()
    send_metered(broker_conn, {
        "type":"LOOKUP",
        "IDC": client_profile["IDC"],
        "request_type": client_profile["request_type"]
    }, "I_to_broker_bytes")
    r = recv_metered(broker_conn, "broker_to_I_bytes")
    metrics["t_lookup"] = time.perf_counter() - t0
    if r.get("type") != "LOOKUP-RESULT":
        return
    if not r["present"]:
        send_metered(client_conn, {"type":"RESULT","status":"IDC not found"}, "I_to_client_bytes")
        return

    # ---- Phase 2(2): get Enc1(y_i) from broker ----
    t0 = time.perf_counter()
    send_metered(broker_conn, {"type":"SEND-ENC1"}, "I_to_broker_bytes")
    enc1s = recv_metered(broker_conn, "broker_to_I_bytes")
    metrics["t_enc1"] = time.perf_counter() - t0
    if enc1s.get("type") != "ENC1-BATCH":
        return

    # ReEnc client Enc2(-x_i) -> Enc1(-x_i), Add with Enc1(y_i), Blind, then send batch
    blinded_batch = {}
    for label, c1 in enc1s["ciphers"].items():
        c_client = client_ciphertexts.get(label)
        if c_client is None:
            continue
        rk = client_rekeys.get("rk_to_broker", 0)
        c_re = ReEnc(c_client, rk)     # -> Enc1(-x_i)
        s = Add(c1, c_re)              # Enc1(y_i - x_i)
        w = random.randint(2, 1_000_000_000)
        s_blind = Blind(s, w)          # zero stays zero
        blinded_batch[label] = s_blind

    # ---- Phase 2(3): MATCH-TEST ----
    t0 = time.perf_counter()
    send_metered(broker_conn, {"type":"MATCH-TEST","ciphers":blinded_batch}, "I_to_broker_bytes")
    verdict = recv_metered(broker_conn, "broker_to_I_bytes")
    metrics["t_match"] = time.perf_counter() - t0
    if verdict.get("type") != "MATCH-RESULTS":
        return

    # ---- Phase 3: forward broker response to client ----
    result_msg = {
        "type": "RESULT",
        "status": verdict["iv_status"],
        "match_labels": verdict["matches"],
        "request_outcome": verdict.get("request_outcome","")
    }
    if "data" in verdict:  # for Access
        result_msg["data"] = verdict["data"]
    send_metered(client_conn, result_msg, "I_to_client_bytes")

    # Print metrics and optional Charm timings
    if DEBUG:
        pretty = {k: (round(v, 6) if isinstance(v, float) else v) for k, v in metrics.items()}
        print("[I] metrics:", pretty)
        if DO_CHARMBENCH:
            try:
                ct = charm_microbench()
                print("[I] charm_microbench (seconds):", {k: round(v, 6) for k, v in ct.items()})
            except Exception as e:
                print("[I] charm_microbench skipped:", e)

def serve():
    print(f"[I] listening on {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        # Read a full JSON line (role + first payload)
        first = b""
        while not first.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            first += chunk
        if not first:
            conn.close()
            continue
        nl = first.find(b"\n")
        header = json.loads(first[:nl].decode("utf-8"))
        rest = first[nl+1:]

        class Shim:
            def __init__(self, conn, buf):
                self.conn = conn
                self.buf = buf
            def recv(self, n):
                if self.buf:
                    out = self.buf[:n]
                    self.buf = self.buf[n:]
                    return out
                return self.conn.recv(n)
            def sendall(self, b):
                return self.conn.sendall(b)
            def close(self):
                return self.conn.close()

        shim = Shim(conn, rest)
        # Put the line back for our recv_metered
        line = json.dumps(header).encode("utf-8") + b"\n" + rest
        shim = Shim(conn, line)
        if header.get("role") == "CLIENT":
            threading.Thread(target=handle_client, args=(shim, addr), daemon=True).start()
        elif header.get("role") == "BROKER":
            threading.Thread(target=handle_broker, args=(shim, addr), daemon=True).start()
        else:
            conn.close()

if __name__ == "__main__":
    serve()
