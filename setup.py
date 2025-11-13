from my_afgh06 import AFGH06
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject

# Initialize
groupObj = PairingGroup('SS512')
pre = AFGH06(groupObj)

# Create params
params = pre.setup()
print("Created params")

import sys

if len(sys.argv) > 1:
    num_brokers = int(sys.argv[1])
else:
    #default
    num_brokers = 500

# Create keys
(pk_c, sk_c) = pre.keygen(params)
# (pk_b, sk_b) = pre.keygen(params)
pkbs = []
skbs = []
for i in range(num_brokers):
    (pk_b, sk_b) = pre.keygen(params)
    pkbs.append(pk_b)
    skbs.append(sk_b)
    if (i + 1) % 50 == 0:
        print(f"  Created {i + 1} key pairs...")

print("Created keys")

# Save params
with open('params.bin', 'wb') as f:
    f.write(objectToBytes(params, groupObj))
print("Saved params to params.bin")

# Save keys
with open('keys.bin', 'wb') as f:
    f.write(objectToBytes((pkbs, skbs, pk_c, sk_c), groupObj))
print("Saved keys to keys.bin")

print("\nSetup complete.")