import IVDrip as iv
import ast 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import socket
import ssl
from charm.core.engine.util import objectToBytes, bytesToObject


HOST = '127.0.0.1'
PORT = 8443
CERT_FILE = 'intermediary.crt'
KEY_FILE = 'intermediary.key'


BROKER_HOST = '127.0.0.1'
BROKER_PORT = 8555
BROKER_CERT = 'server.crt'



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
    host, port, certfile= BROKER_HOST, BROKER_PORT, BROKER_CERT
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certfile)
    ctx.check_hostname = False
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            data = b''.join(len(objectToBytes(o, iv.groupObj)).to_bytes(4, 'big') + objectToBytes(o, iv.groupObj) for o in objs)
            ssock.sendall(data)
            return data


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # receive values,keys from consumer, store
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        print("Intermediary waiting for consumer...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            # with conn:
            objs = receive(conn)
            cs, rs= objs
            print("intermediary received data from consumer")

            # send idc to broker
            m=3 #broker id, just putting random here for now
            idc = "Steve.Jobs@apple.com" #random for now
            send(idc)
            print("Intermediary sent idc to broker")

            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

    # # send idc to broker
    # m=3 #broker id, just putting random here for now
    # idc = "Steve.Jobs@apple.com" #random for now
    # send(idc)
    # print("Intermediary sent idc to broker")


    # receive values from broker
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        print("Intermediary waiting for broker...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                objs = receive(conn)
    ctildes = objs
    print("intermediary received ctildes from broker")

    # perform computation: first need the correct label list (will do later)
    rk = rs[m]
    ais = iv.intermediary(rk,cs,ctildes)

    #send list to broker
    byteais = send(ais)
    print("Intermediary sent ais to broker")

if __name__ == "__main__":
    main()