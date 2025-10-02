# client.py
# Client/consumer process. Start after broker has registered.
#   python client.py --idc JANE-DOE-123 --request delete
import socket, json, argparse, hashlib, os
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

def main(idc: str, request_type: str):
    # Values: some match the broker dataset, some do not
    X = {
        "name": "JANE DOE",                 # match
        "email": "jane@example.com",        # match
        "address": "123 MAIN ST",           # match
        "zip": "92697",                     # match
        "phone": "555-1234",                # non-match
        "dob": "1999-01-01"                 # match
    }
    Xh = {k: h_int(v) for k, v in X.items()}
    if DEBUG:
        print("[client] x hashes:", Xh)

    skC, pkC = KeyGen()
    # Enc2 of -x_i
    ciphers = {k: Enc2(pkC, (-val) % MOD) for k, val in Xh.items()}
    rk = ReEncKeyGen(skC, pkB=None)
    rekeys = {"rk_to_broker": rk}

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
    ap.add_argument("--idc", default="JANE-DOE-123")
    ap.add_argument("--request", default="delete", choices=["delete","access","opt-out"])
    args = ap.parse_args()
    main(args.idc, args.request)
