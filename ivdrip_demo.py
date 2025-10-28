from dataclasses import dataclass
from typing import Dict, List
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR, GT, pair

# ----------------- Normalization helpers -----------------
def canon_email(e: str) -> str:
    return e.strip().lower()

def canon_phone(p: str) -> str:
    return ''.join(ch for ch in p if ch.isdigit())

# ----------------- Minimal PRE (demo) -----------------
class PRE:
   
    def __init__(self, group_name='SS512'):
        self.group = PairingGroup(group_name)
        g = self.group.hash("iv-drip-g", G1)
        self.gT = pair(g, g)   # GT generator for all ops

    # == as-if "public key crypto" ==
    def keygen(self):
        sk = self.group.random(ZR)
        pk = self.gT ** sk
        return pk, sk

    # Deterministic token in GT from a string (email/phone)
    def token(self, s: str):
        h = self.group.hash(s, ZR)
        return self.gT ** h

    # "Second-level" encryption by the consumer using their secret skA
    def encrypt_second_level(self, skA, M_GT):
        return M_GT * (self.gT ** skA)

    # Re-encryption key from A (skA) to B (pkB)
    def rekey(self, skA, pkB):
        return pkB * (self.gT ** (-skA))

    # Intermediary re-encrypts without learning M
    def reencrypt(self, rkAB, ctA):
        return ctA * rkAB

    # Broker decrypts with its secret skB
    def decrypt(self, skB, ctB):
        return ctB * ((self.gT ** skB) ** -1)

# ----------------- Roles -----------------
@dataclass
class Consumer:
    pk: GT
    sk: ZR
    enc_tokens: Dict[str, GT]        # field -> C = M * gT^skA
    rekeys: Dict[str, GT]            # broker_id -> rk_AB

@dataclass
class Broker:
    broker_id: str
    pk: GT
    sk: ZR
    db: Dict[str, GT]                # field -> M (token in GT)

class Intermediary:
    def __init__(self, pre: PRE, brokers: List[Broker]):
        self.pre = pre
        self.brokers = {b.broker_id: b for b in brokers}

    def process_consumer(self, consumer: Consumer) -> Dict[str, Dict[str, bool]]:
     
        results: Dict[str, Dict[str, bool]] = {}
        for bid, broker in self.brokers.items():
            rk = consumer.rekeys[bid]
            # Intermediary transforms each ciphertext for that broker
            ct_for_broker = {fld: self.pre.reencrypt(rk, ct)
                             for fld, ct in consumer.enc_tokens.items()}
            # Broker decrypts and compares with its DB
            matches: Dict[str, bool] = {}
            for fld, ctB in ct_for_broker.items():
                recovered = self.pre.decrypt(broker.sk, ctB)   # GT element
                matches[fld] = (recovered == broker.db.get(fld))
            results[bid] = matches
        return results

# ----------------- Demo wiring -----------------
def main():
    pre = PRE('SS512')
    g = pre.group

    # ---- Brokers with some dummy DB records ----
    bA_pk, bA_sk = pre.keygen()
    bB_pk, bB_sk = pre.keygen()

    broker_A = Broker(
        broker_id="BrokerA",
        pk=bA_pk, sk=bA_sk,
        db={
            "email": pre.token(canon_email("alice@example.com")),
            "phone": pre.token(canon_phone("+1 (415) 555-1234")),
        },
    )
    broker_B = Broker(
        broker_id="BrokerB",
        pk=bB_pk, sk=bB_sk,
        db={
            "email": pre.token(canon_email("nobody@else.com")),
            "phone": pre.token(canon_phone("0000000000")),
        },
    )

    # ---- Consumer encrypts her own identifiers once ----
    c_pk, c_sk = pre.keygen()
    alice_email = pre.token(canon_email("alice@example.com"))
    alice_phone = pre.token(canon_phone("+1 415 555 1234"))

    enc_tokens = {
        "email": pre.encrypt_second_level(c_sk, alice_email),
        "phone": pre.encrypt_second_level(c_sk, alice_phone),
    }

    # Create per-broker re-encryption keys (no plaintext exposure)
    rekeys = {
        broker_A.broker_id: pre.rekey(c_sk, broker_A.pk),
        broker_B.broker_id: pre.rekey(c_sk, broker_B.pk),
    }

    consumer = Consumer(pk=c_pk, sk=c_sk, enc_tokens=enc_tokens, rekeys=rekeys)

    # ---- Intermediary does the routing/transforms ----
    I = Intermediary(pre, [broker_A, broker_B])
    results = I.process_consumer(consumer)

    # ---- Show outcome ----
    print("\n=== IV-Drip Demo Results ===")
    for bid, fields in results.items():
        print(f"{bid}:")
        for fld, ok in fields.items():
            print(f"  {fld:>5}: {'MATCH' if ok else 'no match'}")

    print("\n(Consumer encrypted once. Intermediary only saw ciphertext + rekeys."
          " Each broker only learned whether *their own* record matched.)")

if __name__ == "__main__":
    main()
