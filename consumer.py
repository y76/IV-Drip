import IVDrip as iv
# from IVDrip import IVDrip
import socket, ssl
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject
from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c, pkbs
import time,csv

HOST = '127.0.0.1'
PORT = 8443
SERVER_CERT = 'intermediary.crt'

bytes_sent=0

import sys

if len(sys.argv) > 2:
    num_brokers = int(sys.argv[1])
    num_pii = int(sys.argv[2])
else:
    #default
    num_brokers = 500
    num_pii = 10

def send(objs):
    global bytes_sent
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    ctx.check_hostname = False

    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            data = b''.join(len(objectToBytes(o, groupObj)).to_bytes(4, 'big') + objectToBytes(o, groupObj) for o in objs)
            bytes_sent+=len(data)
            ssock.sendall(data)
            ssock.shutdown(socket.SHUT_WR)


def main():
    # get labels, piilist
    piilist = iv.getPIIList("data.txt")
    full_start = time.time()
    # # get pkb list
    # # can change later to http get

    # encrypt elements and generate re-encryption keys and compute proofs (later)
    cs, rks = iv.consumer(pkbs,piilist.keys(),piilist)

    # send to intermediary
    objs = cs,rks
    send(objs)
    full_end = time.time()
    # print("bytes sent:", bytes_sent)
    # print("stuff sent to intermediary")
    full_runtime=full_end-full_start
    # print("full runtime: ", full_runtime)

    with open('consumer.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([full_runtime, bytes_sent, num_brokers, num_pii])


if __name__ == "__main__":
    main()