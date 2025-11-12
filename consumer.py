import IVDrip as iv
# from IVDrip import IVDrip
import socket, ssl
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject
from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c

HOST = '127.0.0.1'
PORT = 8443
SERVER_CERT = 'intermediary.crt'
# iv = IVDrip(10)

def send(objs):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    ctx.check_hostname = False

    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            data = b''.join(len(objectToBytes(o, groupObj)).to_bytes(4, 'big') + objectToBytes(o, groupObj) for o in objs)
            ssock.sendall(data)
            ssock.shutdown(socket.SHUT_WR)


def main():
    # get labels, piilist
    piilist = iv.getPIIList("data.txt")

    # # get pkb list
    # # can change later to http get

    # encrypt elements and generate re-encryption keys and compute proofs (later)
    cs, rks = iv.consumer(pk_b,piilist.keys(),piilist)

    # send to intermediary
    objs = cs,rks
    send(objs)
    print("stuff sent to intermediary")


if __name__ == "__main__":
    main()