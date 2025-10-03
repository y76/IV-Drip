# client.py
#   python client.py --idc steve_j --request delete --data data/consumer_steve.json
import socket, json, argparse, hashlib, os, csv, time
from typing import Dict, Any
from my_afgh06 import KeyGen, ReEncKeyGen, Enc2  # toy shim ops

HOST = "127.0.0.1"
PORT = 50500
MOD = 1_000_000_007  # shared with broker & shim
DEBUG = os.getenv("DEBUG", "0") == "1"

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

def load_consumer_data(path: str) -> Dict[str, str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Consumer data file not found: {path}")
    ext = os.path.splitext(path)[1].lower()
    ds: Dict[str, str] = {}
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            if not isinstance(obj, dict):
                raise ValueError("JSON must be an object mapping label -> value")
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
        raise ValueError("Consumer dataset is empty after parsing")
    return ds

def main(idc: str, request_type: str, data_path: str):
    t0 = time.perf_counter()
    X = load_consumer_data(data_path)            # arbitrary labels/values
    Xh = {k: h_int(v) for k, v in X.items()}     # deterministic hashing
    if DEBUG:
        print("[client] x hashes:", Xh)

    skC, pkC = KeyGen()
    # Enc2 of -x_i
    ciphers = {k: Enc2(pkC, (-val) % MOD) for k, val in Xh.items()}
    rk = ReEncKeyGen(skC, pkB=None)
    rekeys = {"rk_to_broker": rk}
    if DEBUG:
        print(f"[client] prep_time: {time.perf_counter() - t0:.6f}s")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    req = {
        "role":"CLIENT",
        "type":"REQUEST",
        "IDC": idc,
        "request_type": request_type.capitalize(),  # "Delete", "Access", "Opt-out"
        "pk": pkC.__dict__,
        "ciphertexts": ciphers,
        "rekeys": rekeys
    }
    send(s, req)
    ack = recv(s)
    print("[client] intermediary:", ack)

    res = recv(s)
    print("[client] result:", json.dumps(res, indent=2))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--idc", required=True, help="Public lookup token for the consumer")
    ap.add_argument("--request", default="delete", choices=["delete","access","opt-out"])
    ap.add_argument("--data", required=True, help="Path to consumer dataset (.json, .csv, or key=value .txt)")
    args = ap.parse_args()
    main(args.idc, args.request, args.data)
