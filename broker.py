# broker.py
# Broker process. Start after intermediary is listening.
#   python broker.py --id B1
import socket, json, argparse, hashlib, os
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

def main(broker_id: str):
    dataset = {
        "name": "JANE DOE",
        "email": "jane@example.com",
        "address": "123 MAIN ST",
        "zip": "92697",
        "phone": "555-0101",
        "dob": "1999-01-01"
    }

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
            # Remember request type for later policy/action
            current_req_type = msg.get("request_type", "Delete")
            present = True  # toy: always present if IDC sent
            send(s, {"type":"LOOKUP-RESULT","present": present})

        elif msg["type"] == "SEND-ENC1":
            # Return Enc1(y_i) per label using deterministic hashing
            hashed = {k: h_int(v) for k, v in dataset.items()}
            if DEBUG:
                print("[broker] y hashes:", hashed)
            ciphers = {k: Enc1(pk=None, m=hashed[k]) for k in dataset.keys()}
            send(s, {"type":"ENC1-BATCH","ciphers": ciphers})

        elif msg["type"] == "MATCH-TEST":
            matches = []
            for k, c in msg["ciphers"].items():
                v = ParDec(skB, c)  # 0 means match
                if v == 0:
                    matches.append(k)

            iv_ok = len(matches) >= THRESH
            if iv_ok:
                if current_req_type == "Access":
                    # For demo: return matched fields in plaintext
                    data = {k: dataset[k] for k in matches}
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
    args = ap.parse_args()
    main(args.id)
