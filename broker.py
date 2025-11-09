import IVDrip as iv
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import socket
import ssl
from charm.core.engine.util import objectToBytes, bytesToObject

HOST = '127.0.0.1'
PORT = 8555
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

INTERMEDIARY_PORT = 8443
INTERMEDIARY_CERT = 'intermediary.crt'


def receive(conn):
    data = b''
    while True:
        packet = conn.recv(4096)
        if not packet:
            break
        data += packet

    # parse charm objects
    objs = []
    idx = 0
    while idx < len(data):
        length = int.from_bytes(data[idx:idx+4], 'big')
        idx += 4
        obj_bytes = data[idx:idx+length]
        idx += length
        obj = bytesToObject(obj_bytes, iv.groupObj)
        objs.append(obj)
    return objs
    


def send(objs):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=INTERMEDIARY_CERT)
    ctx.check_hostname = False
    with socket.create_connection((HOST, INTERMEDIARY_PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            data = b''.join(len(objectToBytes(o, iv.groupObj)).to_bytes(4, 'big') + objectToBytes(o, iv.groupObj) for o in objs)
            ssock.sendall(data)


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    broker_id = 3 #random id, can change later i guess.

    # receive id from intermediary and lookup ID
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        print(f"Broker listening on {HOST}:{PORT}...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
    idc=objs
    print("Broker received IDc from intermediary")
    #assume successful IDc lookup, get piilist
    piilist = iv.getPIIList("data.txt")
    # Encrypt pii under its own pk -> ctildes
    pkb=iv.pkbs[broker_id]
    ctildes = iv.broker_enc(pkb,piilist)

    # send ctildes to intermediary
    send(ctildes)
    print("Broker sent ctildes to intermediary")
    # receive ais from intermediary
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        print(f"Broker listening on {HOST}:{PORT}...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
    ais=objs
    print("Broker received ais from intermediary")
    #get result of PLI and output intersection
    intersec = iv.broker_pli(iv.skbs[broker_id],ais)
    print("intersection is: ", intersec)

if __name__ == "__main__":
    main()