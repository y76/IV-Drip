# from charm.toolbox.pairinggroup import PairingGroup
# group = PairingGroup('SS512')
# print(group.random())


# from charm.schemes.prenc.pre_afgh06 import AFGH06
from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PREnc import PREnc

# group = PairingGroup('SS512')
# pre = AFGH06(group)

# print("Available methods in pre:")
# print(dir(pre))  # Check if 'expm' is listed

# params = pre.setup()
# msg = group.random(ZR)
# print("Result from expm:", pre.expm(params, msg))

groupObj = PairingGroup('SS512')
# group = PairingGroup('SS512')
pre = AFGH06(groupObj)
print(type(pre))
params = pre.setup()
(pk_a, sk_a) = pre.keygen(params)
(pk_b, sk_b) = pre.keygen(params)
# msg = groupObj.random(GT)
msg = groupObj.random(ZR)
c_a = pre.encrypt(params, pk_a, msg)
rk = pre.rekeygen(params, pk_a, sk_a, pk_b, sk_b)
c_b = pre.re_encrypt(params, rk, c_a)
print(pre.expm(params,msg))
# print(gm)
print(pre.decrypt(params, sk_b, c_b))

# ---- identity checks ----
zero = groupObj.init(ZR, 0)

oneG1 = groupObj.init(G1, 1)
oneG2 = groupObj.init(G2, 1)
oneGT = groupObj.init(GT, 1)

print("G1 identity == g**0 ? ", (params['g'] ** zero) == oneG1)
print("G2 identity (pairing base) sanity: ", isinstance(oneG2, type(oneG2)))  # optional
print("GT identity == Z**0 ? ", (params['Z'] ** zero) == oneGT)

# check your expm helper at m=0:
print("expm(Z, 0) == 1_GT ? ", pre.expm(params, zero) == oneGT)
