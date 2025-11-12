from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PREnc import PREnc
from charm.core.engine.util import objectToBytes,bytesToObject


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

from config import groupObj, pre, params, pk_b, sk_b, pk_c, sk_c

def consumer(pkb, plabels, piilist):
    cs = {}
    # print(params)
    for label in plabels:
        if label in piilist:
            msg = -groupObj.hash(piilist[label],ZR)
            cs[label] = pre.encrypt(params,pk_c,msg)
        else:
            msg = groupObj.random(ZR)
            cs[label] = pre.encrypt(params,pk_c,msg)
    
    rks = []
    # for p in pkb:
    rk = pre.rekeygen(params, pk_c, sk_c, pkb)
    rks.append(rk)
    return cs,rks

def intermediary(rk, cs, ctildes):
    res = {}
    # print(params)
    for label in ctildes:
        reenc = pre.re_encrypt(params, rk, cs[label])
        cp = pre.add(ctildes[label], reenc)
        wi = groupObj.random(ZR)
        r1 = cp['c1']**wi
        r2 = cp['c2']**wi
        res[label] = { 'c1' : r1, 'c2' : r2 }
    return res


def broker_enc(pkb, piilist):
    res = {}
    # print(params)
    for label in piilist:
        msg = groupObj.hash(piilist[label],ZR)
        res[label] = pre.fencrypt(params,pkb,msg)
    return res

def broker_pli(skb, intersec):
    res = []
    # print(params)
    identity = params['Z'] ** 0
    for label in intersec:
        Z_m = pre.decrypt(params, skb, intersec[label])
        if Z_m == identity:
            res.append(label)
    return res

def getPIIList(filename):
    PIIList = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.split(':', 1) 
            PIIList[key.strip()] = value.strip()
    return PIIList
