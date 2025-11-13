from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject

# Initialize
groupObj = PairingGroup('SS512')
pre = AFGH06(groupObj)

# Load params
with open('params.bin', 'rb') as f:
    params = bytesToObject(f.read(), groupObj)
print(f"Loaded params.")

# Load keys
with open('keys.bin', 'rb') as f:
    data = bytesToObject(f.read(), groupObj)
    pkbs, skbs, pk_c, sk_c = data
    pk_b = pkbs[0]
    sk_b=skbs[0]
print(f"Loaded keys.")