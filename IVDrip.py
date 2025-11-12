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
# groupObj = PairingGroup('SS512')
# pre = AFGH06(groupObj)
# params = pre.setup()

# pkbs=[]
# skbs=[]
# (pk_c, sk_c) = pre.keygen(params)
# for i in range(10):
#     (pk_b, sk_b) = pre.keygen(params)
#     pkbs.append(pk_b)
#     skbs.append(sk_b)
class IVDrip:
    def __init__(self, num_brokers=10):
        self.groupObj = PairingGroup('SS512')
        self.pre = AFGH06(self.groupObj)
        self.params = self.pre.setup()
        
        # Initialize keys
        self.pkbs = []
        self.skbs = []
        (self.pk_c, self.sk_c) = self.pre.keygen(self.params)
        
        for i in range(num_brokers):
            (pk_b, sk_b) = self.pre.keygen(self.params)
            self.pkbs.append(pk_b)
            self.skbs.append(sk_b)

    def consumer(self,pkb, plabels,piilist):
        # (pk_c, sk_c) = pre.keygen(params)
        cs = {}
        # print(params)
        for label in plabels:
            if label in piilist:
                msg = -self.groupObj.hash(piilist[label],ZR)
                ################################
                msg=-msg
                ################################
                cs[label] = self.pre.encrypt(self.params,self.pk_c,msg)
                # print(label)
                # c=cs[label]
                # c1 = c['c1'] 
                # c2 = c['c2']
                # m = c2 / (pair(c1,params['g']) ** (sk_c['sk1']))
                # print(m)
                # msg = groupObj.hash(piilist[label],ZR)
                # print(params['Z']**msg)
                # print()
                # test = pre.fencrypt(params,pk_c,msg)
                # test1 = pre.fencrypt(params,pk_c,-msg)
                # addd = pre.add(test,test1)
                # deccc = pre.decrypt(params,sk_c,addd)
                # print(deccc)
                # print()
                # TODO: compute zkp
            else:
                msg = self.groupObj.random(ZR)
                cs[label] = self.pre.encrypt(self.params,self.pk_c,msg)
                # TODO: compute zkp
        # print(cs)
        rks = []
        for p in pkb:
            rk = self.pre.rekeygen(self.params, self.pk_c, self.sk_c, p)
            rks.append(rk)
        return cs,rks

    def intermediary(self,rk,cs,ctildes):
        res = {}
        # print(ctildes)
        # print(pre.decrypt(params,skbs[3],ctildes['firstName']))
        # print(skbs[3])
        # print(params)
        for label in ctildes:
            # print(label)
            # print(pre.decrypt(params,skbs[3],ctildes[label]))
            reenc = self.pre.re_encrypt(self.params, rk, cs[label])
            # c=cs[label]
            # c1 = c['c1'] 
            # c2 = c['c2']
            # m = c2 / (pair(c1,params['g']) ** (sk_c['sk1']))
            # print(m)
            # print(pre.decrypt(params,skbs[3],reenc))
            # msg = groupObj.hash("A1B2C3D4E5F6",ZR)
            # print(params['Z']**msg)
            # print()
            cp = self.pre.add(ctildes[label],reenc)
            #check here
            wi = self.groupObj.random(ZR)
            r1 = cp['c1']**wi
            r2 = cp['c2']**wi
            #check here
            res[label] = { 'c1' : r1, 'c2' : r2 }
        return res


    def broker_enc(self,pkb,piilist):
        res = {}
        for label in piilist:
            msg = self.groupObj.hash(piilist[label],ZR)
            res[label] = self.pre.fencrypt(self.params,pkb,msg)
            # print(pre.decrypt(params,skbs[3],res[label]))
        # print(pre.decrypt(params,skbs[3],res['firstName']))
        # print(skbs[3])
        return res

    def broker_pli(self,skb, intersec):
        res = []
        # print(params)
        for label in intersec:
            # print(pre.decrypt(params, skb, intersec[label]), groupObj.init(GT, 1), pre.expm(params, groupObj.init(ZR, 0)))
            # print()
            identity = self.params['Z'] ** 0
            Z_m=self.pre.decrypt(self.params, skb, intersec[label])
            if self.pre.decrypt(self.params, skb, intersec[label]) == self.groupObj.init(GT, 1):
                res.append(label)
        return res

    def getPIIList(self,filename):
        PIIList = {}
        with open(filename, 'r') as file:
            for line in file:
                key, value = line.split(':', 1) 
                PIIList[key.strip()] = value.strip()

        return PIIList