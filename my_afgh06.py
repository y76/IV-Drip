'''
AFGH Proxy Re-Encryption
| From: Ateniese, G., Fu, K., Green, M., & Hohenberger, S. (2006). Improved proxy re-encryption schemes with applications to secure distributed storage. 
| Published in: ACM Transactions on Information and System Security (TISSEC), 9(1), 1-30.
| Available from: http://dl.acm.org/citation.cfm?id=1127346
* type:           proxy encryption
* properties:     CPA-secure, unidirectional, single-hop, non-interactive, collusion-resistant
* setting:        Pairing groups (Type 1 "symmetric")
* assumption:     eDBDH (Extended Decisional Bilinear DH)
* to-do:          first-level encryption & second-level decryption
:Authors:    D. Nuñez
:Date:       04/2016
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.PREnc import PREnc

debug = False

class AFGH06(PREnc):
    """
    Quick self-test example in the docstring.
    """
    def __init__(self, groupObj):
        global group
        group = groupObj
        
    def setup(self):
        g = group.random(G1)
        Z = pair(g, g)
        params = {'g': g, 'Z': Z}
        if debug:
            print("Setup: Public parameters...")
            group.debug(params)
        return params

    def keygen(self, params):
        x1, x2 = group.random(ZR), group.random(ZR)
        Z_x1 = params['Z'] ** x1
        g_x2 = params['g'] ** x2
        sk = {'sk1': x1, 'sk2': x2}
        pk = {'pk1': Z_x1, 'pk2': g_x2}
        if debug:
            print('\nKeygen...')
            print("pk => '%s'" % pk)
            print("sk => '%s'" % sk)
        return (pk, sk)

    def rekeygen(self, params, pk_a, sk_a, pk_b, sk_b):
        pk_b2 = pk_b['pk2']
        sk_a1 = sk_a['sk1']
        rk = pk_b2 ** sk_a1
        if debug:
            print('\nReKeyGen...')
            print("rk => '%s'" % rk)
        return rk

    def encrypt(self, params, pk, m):
        # First-level encryption (re-encryptable)
        r = group.random(ZR)
        Z_a1 = pk['pk1']
        c1 = params['g'] ** r
        c2 = (params['Z'] ** m) * (Z_a1 ** r)
        c = {'c1': c1, 'c2': c2}
        if debug:
            print('\nEncrypt...')
            print('m => %s' % m)
            print('r => %s' % r)
            group.debug(c)
        return c

    def expm(self, params, m):
        # Encode an integer m as Z^m in GT
        gm = (params['Z'] ** m)
        return gm
        
    def decrypt(self, params, sk, c):
        # Returns Z^m in GT (not the integer m), matching expm() encoding
        c1 = c['c1']
        c2 = c['c2']
        m = c2 / (c1 ** (~sk['sk2']))
        if debug:
            print('\nDecrypt...')
            print('m => %s' % m)
        return m
        
    def re_encrypt(self, params, rk, c_a):
        # Re-encrypt first-level under A into second-level under B
        c1 = c_a['c1'] 
        c2 = c_a['c2']
        c1_prime = pair(c1, rk)
        c_b = {'c1': c1_prime, 'c2': c2}
        if debug:
            print('\nRe-encrypt...')
            group.debug(c_b)
        return c_b


# ---------------------------------------------------------------------------
# Compatibility shim for socket demo (NOT cryptographically secure)
# API: KeyGen, ReEncKeyGen, Enc1, Enc2, ReEnc, Add, Blind, ParDec
# ---------------------------------------------------------------------------

import secrets, time
from dataclasses import dataclass
from typing import Tuple, Any, Dict
import json as _json

# Shared modulus for toy arithmetic — must match client/broker
P = 1_000_000_007

@dataclass
class SK:
    a1: int
    a2: int

@dataclass
class PK:
    Za1: int
    g_a2: int

def KeyGen() -> Tuple[SK, PK]:
    a1 = secrets.randbelow(P - 2) + 2
    a2 = secrets.randbelow(P - 2) + 2
    g = 5
    Z = 7
    Za1 = pow(Z, a1, P)
    g_a2 = pow(g, a2, P)
    return SK(a1=a1, a2=a2), PK(Za1=Za1, g_a2=g_a2)

def ReEncKeyGen(skA: SK, pkB: PK) -> int:
    return skA.a1

def Enc1(pk: PK, m: int):
    return ('enc1', m % P)

def Enc2(pk: PK, m: int):
    return ('enc2', m % P)

def ReEnc(c12, rkAtoB: int):
    tag, val = c12
    if tag != 'enc2':
        raise ValueError("ReEnc expects a second-level ciphertext")
    return ('enc1', val)

def Add(c1, c2):
    t1, v1 = c1
    t2, v2 = c2
    if t1 != 'enc1' or t2 != 'enc1':
        raise ValueError("Add expects first-level ciphertexts")
    return ('enc1', (v1 + v2) % P)

def Blind(c, w: int):
    t, v = c
    if t != 'enc1':
        raise ValueError("Blind expects first-level ciphertext")
    return ('enc1', (v * w) % P)

def ParDec(sk: SK, c):
    t, v = c
    if t not in ('enc1', 'enc2'):
        raise ValueError("Unknown ciphertext type")
    return 0 if (v % P) == 0 else (v % P)

def json_dumps(obj: Any) -> bytes:
    return _json.dumps(obj, separators=(",", ":")).encode("utf-8")

def bytes_len(obj: Any) -> int:
    return len(json_dumps(obj))

# ---- Optional: Charm micro-bench for timings (set CHARM_BENCH=1 to enable) ----
def charm_microbench() -> Dict[str, float]:
    """
    Runs a tiny AFGH06 cycle to measure setup/keygen/encrypt/rekey/reenc/decrypt.
    Returns a dict of seconds measured with time.perf_counter().
    """
    t = {}
    t0 = time.perf_counter()
    grp = PairingGroup('SS512')
    pre = AFGH06(grp)
    t['group_init'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    params = pre.setup()
    t['setup'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    pk_a, sk_a = pre.keygen(params)
    pk_b, sk_b = pre.keygen(params)
    t['keygen_2x'] = time.perf_counter() - t0

    m = grp.random(GT)
    t0 = time.perf_counter()
    c_a = pre.encrypt(params, pk_a, m)
    t['encrypt'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    rk = pre.rekeygen(params, pk_a, sk_a, pk_b, sk_b)
    t['rekeygen'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    c_b = pre.re_encrypt(params, rk, c_a)
    t['re_encrypt'] = time.perf_counter() - t0

    t0 = time.perf_counter()
    _ = pre.decrypt(params, sk_b, c_b)
    t['decrypt'] = time.perf_counter() - t0
    return t
