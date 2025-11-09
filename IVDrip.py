from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PREnc import PREnc


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
groupObj = PairingGroup('SS512')
pre = AFGH06(groupObj)
params = pre.setup()

pkbs=[]
skbs=[]
for i in range(10):
    (pk_b, sk_b) = pre.keygen(params)
    pkbs.append(pk_b)
    skbs.append(sk_b)

def consumer(pkb, plabels,piilist):
    (pk_c, sk_c) = pre.keygen(params)
    cs = {}
    for label in plabels:
        if label in piilist:
            cs[label] = pre.encrypt(params,pk_c,-piilist[label])
            # TODO: compute zkp
        else:
            msg = groupObj.random(ZR)
            cs[label] = pre.encrypt(params,pk_c,msg)
            # TODO: compute zkp
    rks = []
    for p in pkb:
        rk = pre.rekeygen(params, pk_c, sk_c, p)
        rks.append(rk)
    return cs,rks

def intermediary(rk,cs,ctildes):
    res = {}
    for label in ctildes:
        reenc = pre.re_encrypt(params, rk, cs[label])
        cp = pre.add(ctildes[label],reenc)
        wi = groupObj.random(ZR)
        r1 = cp['c1']**wi
        r2 = cp['c2']**wi
        res[label] = { 'c1' : r1, 'c2' : r2 }
    return res


def broker_enc(pkb,piilist):
    res = {}
    for label in piilist:
        res[label] = pre.encrypt(params,pkb,piilist)
    return res

def broker_pli(skb, intersec):
    res = []
    for label in intersec:
        if pre.decrypt(params, skb, intersec[label]) == groupObj.init(GT, 1):
            res.append(label)
    return res

def getPIIList(filename):
    PIIList = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.split(':', 1) 
            PIIList[key.strip()] = value.strip()

    return PIIList