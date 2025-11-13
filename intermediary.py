import IVDrip as iv
# from IVDrip import IVDrip
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import socket
import ssl
from charm.core.engine.util import objectToBytes, bytesToObject
from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c
import time, csv

HOST = '127.0.0.1'
PORT = 8443
CERT_FILE = 'intermediary.crt'
KEY_FILE = 'intermediary.key'


BROKER_HOST = '127.0.0.1'
BROKER_PORT = 8555
BROKER_CERT = 'server.crt'
# iv = IVDrip(10)

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
    return objs


def send(objs):
    global bytes_sent
    host, port, certfile= BROKER_HOST, BROKER_PORT, BROKER_CERT
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certfile)
    ctx.check_hostname = False
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            if isinstance(objs, list):
                data = b''.join(len(objectToBytes(o, groupObj)).to_bytes(4, 'big') + objectToBytes(o, groupObj) for o in objs)
            else :
                obj_bytes = objectToBytes(objs, groupObj)
                data = len(obj_bytes).to_bytes(4, 'big') + obj_bytes
            bytes_sent += len(data)
            ssock.sendall(data)
            # print(data)
            ssock.shutdown(socket.SHUT_WR)



def main():

    full_start = time.time()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # receive values,keys from consumer, store
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        # print("Intermediary waiting for consumer...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
        # sock.close()
    cs, rs= objs
    # print("intermediary received data from consumer")

    # send idc to broker
    idc = "Steve.Jobs@apple.com" #random for now
    send(idc)
    # print("Intermediary sent idc to broker")


    # receive values from broker
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        sock.bind((HOST, 8444))
        sock.listen(1)
        # print("Intermediary waiting for broker...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
        # sock.close()
    ctildes = objs[0]
    # print("intermediary received ctildes from broker")

    # perform computation: first need the correct label list (will do later)
    rk = rs[0] # broker is first
    ais = iv.intermediary(rk,cs,ctildes)

    #send list to broker
    send(ais)
    full_end = time.time()
    # print("Intermediary sent ais to broker")

    # print("bytes sent:", bytes_sent)
    # print("bytes received:", bytes_received)
    full_runtime = full_end-full_start
    # print("full runtime: ", full_end-full_start)

    with open('intermediary.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([full_runtime, bytes_sent, bytes_received, num_brokers, num_pii])    

if __name__ == "__main__":
    main()