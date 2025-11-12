from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject

# Initialize
groupObj = PairingGroup('SS512')
pre = AFGH06(groupObj)

# Create params
params = pre.setup()
print("Created params")

# Create keys
(pk_c, sk_c) = pre.keygen(params)
(pk_b, sk_b) = pre.keygen(params)
print("Created keys")

# Save params
with open('params.bin', 'wb') as f:
    f.write(objectToBytes(params, groupObj))
print("Saved params to params.bin")

# Save keys
with open('keys.bin', 'wb') as f:
    f.write(objectToBytes((pk_b, sk_b, pk_c, sk_c), groupObj))
print("Saved keys to keys.bin")

print("\nSetup complete.")