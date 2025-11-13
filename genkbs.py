import IVDrip as iv
from my_afgh06 import AFGH06

m=10
for i in range(10):
    (pk_b, sk_b) = iv.pre.keygen(iv.params)
    with open("pkbs.txt", "a") as f:
        f.write(f"{pk_b}\n")
