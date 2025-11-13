from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PREnc import PREnc
from charm.core.engine.util import objectToBytes,bytesToObject
import time, csv

## TEST
# groupObj = PairingGroup('SS512')
# pre = AFGH06(groupObj)
# print(type(pre))
# params = pre.setup()
# (pk_a, sk_a) = pre.keygen(params)
# (pk_b, sk_b) = pre.keygen(params)
# # msg = groupObj.random(GT)
# msg = groupObj.random(ZR)
# c_a = pre.encrypt(params, pk_a, msg)
# rk = pre.rekeygen(params, pk_a, sk_a, pk_b)
# c_b = pre.re_encrypt(params, rk, c_a)
# print(pre.expm(params,msg))
# print(pre.decrypt(params, sk_b, c_b))


### ACTUAL CODE. TODO: ZERO KNOWLEDGE PROOFS

from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c, pkbs

def consumer(pkb,plabels, piilist):
    cs = {}
    encrypt_start = time.time()
    for label in plabels:
        if label in piilist:
            msg = -groupObj.hash(piilist[label],ZR)
            cs[label] = pre.encrypt(params,pk_c,msg)
        else:
            msg = groupObj.random(ZR)
            cs[label] = pre.encrypt(params,pk_c,msg)
    encrypt_end=time.time()

    ###########################################################
    # Only for analysis.

    # noI_encrypt_start = time.time()
    # smallList= dict(list(piilist.items())[:10])
    # for pk in pkbs:
    #     for label in smallList:
    #         msg = -groupObj.hash(smallList[label],ZR)
    #         cs[label] = pre.encrypt(params,pk,msg)
    # noI_encrypt_end=time.time()
    # # print("If no intermediary encrypt time: ", noI_encrypt_end-noI_encrypt_start)
    # f= open('noI.csv', 'a')
    # toAppend = str(noI_encrypt_end-noI_encrypt_start) + "\n"
    # f.write(toAppend)
    # f.close()

    ###########################################################

    rkgen_start=time.time()
    rks = []
    for p in pkbs:
        rk = pre.rekeygen(params, pk_c, sk_c, p)
        rks.append(rk)
    rkgen_end=time.time()
    # print(encrypt_end-encrypt_start,rkgen_end-rkgen_start)
    # rks = rks[0] # this is just for now. will modify later
    f= open('exTimes.csv', 'a')
    toAppend = str(encrypt_end-encrypt_start) + "," + str(rkgen_end-rkgen_start) + ","
    f.write(toAppend)
    f.close()
    return cs,rks

def intermediary(rk, cs, ctildes):
    res = {}
    start_time = time.time()
    for label in ctildes:
        reenc = pre.re_encrypt(params, rk, cs[label])
        cp = pre.add(ctildes[label], reenc)
        wi = groupObj.random(ZR)
        r1 = cp['c1']**wi
        r2 = cp['c2']**wi
        res[label] = { 'c1' : r1, 'c2' : r2 }
    end_time=time.time()
    # print(end_time-start_time)
    f= open('exTimes.csv', 'a')
    toAppend = str(end_time-start_time) + ","
    f.write(toAppend)
    f.close()
    return res


def broker_enc(pkb, piilist):
    res = {}
    enc_start=time.time()
    for label in piilist:
        msg = groupObj.hash(piilist[label],ZR)
        res[label] = pre.fencrypt(params,pkb,msg)
    enc_end=time.time()
    # print(enc_end-enc_start)
    f= open('exTimes.csv', 'a')
    toAppend = str(enc_end-enc_start) + ","
    f.write(toAppend)
    f.close()
    return res

def broker_pli(skb, intersec):
    res = []
    dec_start=time.time()
    identity = params['Z'] ** 0
    for label in intersec:
        Z_m = pre.decrypt(params, skb, intersec[label])
        if Z_m == identity:
            res.append(label)
    dec_end=time.time()
    # print(dec_end-dec_start)
    f= open('exTimes.csv', 'a')
    toAppend = str(dec_end-dec_start) + "\n"
    f.write(toAppend)
    f.close()
    return res

def getPIIList(filename):
    PIIList = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.split(':', 1) 
            PIIList[key.strip()] = value.strip()
    return PIIList

