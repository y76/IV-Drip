# broker.py
#   python broker.py --id B1 --data data/broker.json
#   python broker.py --id B1 --data data/broker.csv
#   python broker.py --id B1 --data data/broker.txt
import socket, json, argparse, hashlib, os, csv, time
from typing import Dict, Any
from my_afgh06 import KeyGen, Enc1, ParDec  # toy shim ops

HOST = "127.0.0.1"
PORT = 50500
MOD = 1_000_000_007  # shared with client & shim
DEBUG = os.getenv("DEBUG", "0") == "1"
THRESH = int(os.getenv("IV_MATCH_THRESHOLD", "3"))

def h_int(s: str) -> int:
    # Deterministic (process-independent) integer hash
    if isinstance(s, str):
        s = s.encode("utf-8")
    return int.from_bytes(hashlib.blake2b(s, digest_size=8).digest(), "big") % MOD

def send(sock, msg: Dict[str,Any]):
    sock.sendall(json.dumps(msg).encode("utf-8") + b"\n")

def recv(sock) -> Dict[str,Any]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return json.loads(data.decode("utf-8"))

def load_dataset(path: str) -> Dict[str, str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")
    ext = os.path.splitext(path)[1].lower()
    ds: Dict[str, str] = {}
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            if not isinstance(obj, dict):
                raise ValueError("JSON dataset must be an object mapping label -> value")
            ds = {str(k): str(v) for k, v in obj.items()}
    elif ext == ".csv":
        # Expect two columns: label,value (with or without header)
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].strip().startswith("#"):
                    continue
                if len(row) < 2:
                    if len(row) == 1 and row[0].strip().lower() in {"label","value"}:
                        continue
                    raise ValueError("CSV must have two columns: label,value")
                label, value = row[0].strip(), row[1].strip()
                if label:
                    ds[label] = value
    else:
        # key=value per line; ignore blank lines and leading '#'
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" not in s:
                    raise ValueError("TXT lines must be key=value")
                k, v = s.split("=", 1)
                ds[k.strip()] = v.strip()
    if not ds:
        raise ValueError("Dataset is empty after parsing")
    return ds

def main(broker_id: str, data_path: str):
    dataset = load_dataset(data_path)

    skB, pkB = KeyGen()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    send(s, {"role":"BROKER","type":"REGISTER","broker":{
        "id": broker_id, "pk": pkB.__dict__, "dataset": dataset
    }})
    _ = recv(s)  # ACK

    current_req_type = "Delete"

    while True:
        msg = recv(s)
        if msg["type"] == "LOOKUP":
            current_req_type = msg.get("request_type", "Delete")
            present = True  # toy: assume present when IDC arrives
            send(s, {"type":"LOOKUP-RESULT","present": present})

        elif msg["type"] == "SEND-ENC1":
            t0 = time.perf_counter()
            hashed = {k: h_int(v) for k, v in dataset.items()}
            ciphers = {k: Enc1(pk=None, m=hashed[k]) for k in dataset.keys()}
            if DEBUG:
                print("[broker] y hashes:", hashed)
                print(f"[broker] t_enc1: {time.perf_counter() - t0:.6f}s")
            send(s, {"type":"ENC1-BATCH","ciphers": ciphers})

        elif msg["type"] == "MATCH-TEST":
            t0 = time.perf_counter()
            matches = []
            for k, c in msg["ciphers"].items():
                v = ParDec(skB, c)  # 0 means match
                if v == 0:
                    matches.append(k)
            t_match_local = time.perf_counter() - t0
            if DEBUG:
                print(f"[broker] t_match_local: {t_match_local:.6f}s")

            iv_ok = len(matches) >= THRESH
            if iv_ok:
                if current_req_type == "Access":
                    data = {k: dataset.get(k, "") for k in matches}
                    outcome = "Access granted"
                    send(s, {"type":"MATCH-RESULTS","matches": matches,
                             "iv_status": outcome, "request_outcome": outcome, "data": data})
                elif current_req_type == "Opt-out":
                    outcome = "Opt-out recorded"
                    send(s, {"type":"MATCH-RESULTS","matches": matches,
                             "iv_status": outcome, "request_outcome": outcome})
                else:
                    outcome = "Data deleted"
                    send(s, {"type":"MATCH-RESULTS","matches": matches,
                             "iv_status": outcome, "request_outcome": outcome})
            else:
                outcome = "Cannot verify identity"
                send(s, {"type":"MATCH-RESULTS","matches": matches,
                         "iv_status": outcome, "request_outcome": outcome})
        else:
            break

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", default="B1")
    ap.add_argument("--data", required=True, help="Path to dataset file (.json, .csv, or key=value .txt)")
    args = ap.parse_args()
    main(args.id, args.data)
