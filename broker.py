import IVDrip as iv
# from IVDrip import IVDrip
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import socket
import ssl
from charm.core.engine.util import objectToBytes, bytesToObject
from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c
import random, time, csv

HOST = '127.0.0.1'
PORT = 8555
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

INTERMEDIARY_PORT = 8444
INTERMEDIARY_CERT = 'intermediary.crt'

bytes_sent=0
bytes_received=0

import sys

if len(sys.argv) > 2:
    num_brokers = int(sys.argv[1])
    num_pii = int(sys.argv[2])
else:
    #default
    num_brokers = 500
    num_pii = 10

def receive(conn):
    global bytes_received
    data = b''
    while True:
        try:
            packet = conn.recv(4096)
            if not packet:  # Connection closed gracefully
                break
            data += packet
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            # Connection closed by peer
            break

    bytes_received += len(data)

    # parse charm objects
    objs = []
    idx = 0
    # print(data)
    while idx < len(data):
        length = int.from_bytes(data[idx:idx+4], 'big')
        idx += 4
        obj_bytes = data[idx:idx+length]
        idx += length
        obj = bytesToObject(obj_bytes, groupObj)
        objs.append(obj)
    # objs = bytesToObject(data, groupObj)
    return objs
    


def send(objs):
    global bytes_sent
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=INTERMEDIARY_CERT)
    ctx.check_hostname = False
    with socket.create_connection((HOST, INTERMEDIARY_PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            obj_bytes = objectToBytes(objs, groupObj)
            data = len(obj_bytes).to_bytes(4, 'big') + obj_bytes
            # data = b''.join(len(objectToBytes(o, iv.groupObj)).to_bytes(4, 'big') + objectToBytes(o, iv.groupObj) for o in objs)
            ssock.sendall(data)
            bytes_sent += len(data)
            ssock.shutdown(socket.SHUT_WR)
            # print(data)
            # ssock.shutdown(socket.SHUT_WR)


def main():
    full_start =time.time()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    broker_id = 0 #random id, can change later i guess.

    # receive id from intermediary and lookup ID
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        # print(f"Broker listening on {HOST}:{PORT}...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
    idc=objs
    # print("Broker received IDc from intermediary")
    #assume successful IDc lookup, get piilist
    fullpiilist = iv.getPIIList("data.txt")
    if num_pii == 30:
        piilist = fullpiilist
    else:
        piilist = dict(list(fullpiilist.items())[:num_pii])
    # print(piilist)
    # piilist['firstName'] = "George"
    # Encrypt pii under its own pk -> ctildes
    pkb=pk_b
    ctildes = iv.broker_enc(pkb,piilist)

    # send ctildes to intermediary
    send(ctildes)
    # print("Broker sent ctildes to intermediary")

    # receive ais from intermediary
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        # print(f"Broker listening on {HOST}:{PORT}...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
    ais=objs[0]
    # ais=objs
    # print("Broker received ais from intermediary")
    #get result of PLI and output intersection
    intersec = iv.broker_pli(sk_b,ais)
    full_end=time.time()
    # print("intersection is: ", intersec)
    # print("bytes sent:", bytes_sent)
    # print("bytes received:", bytes_received)
    full_runtime = full_end-full_start
    # print("full runtime: ", full_end-full_start)

    with open('broker.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([full_runtime, bytes_sent, bytes_received, num_brokers, num_pii])  

if __name__ == "__main__":
    main()