"""Mini Project 5.1 - Part A: Simplified cellular-style mutual authentication (software-only).
Models GSM A3/A8 (RAND, Ki -> SRES, Kc) and the UMTS/LTE/5G AKA idea. Standard library only."""
import hashlib, hmac, secrets, random

# ---------- primitives ----------
def generate_rand():                       # called only by HomeNetwork, once per attempt
    return secrets.token_bytes(16)         # 128-bit fresh, unpredictable challenge (RAND)

def compute_response(K, rand):             # A3-style: SRES/RES = HMAC-SHA256(K, RAND)
    return hmac.new(K, rand, hashlib.sha256).digest()

def derive_session_key(K, rand):           # A8 / CK-IK style: distinct label -> distinct output
    return hmac.new(K, b"SESSIONKEY" + rand, hashlib.sha256).digest()

def compute_autn(K, rand):                 # network token so the device can authenticate the network (Task 3)
    return hmac.new(K, b"AUTN" + rand, hashlib.sha256).digest()[:16]

# Why infeasible: HMAC-SHA256 is a one-way keyed pseudorandom function. Seeing (RAND, RES) pairs
# reveals nothing about K and gives no way to predict HMAC(K, RAND2) for an unseen RAND2.

# ---------- entities ----------
class Device:                              # ~ SIM/USIM holding Ki/K
    def __init__(self, K): self._K = K
    def respond(self, rand, autn=None):
        if autn is not None and not hmac.compare_digest(autn, compute_autn(self._K, rand)):
            return None                    # network failed to authenticate itself -> device aborts
        return compute_response(self._K, rand)
    def session_key(self, rand): return derive_session_key(self._K, rand)

class HomeNetwork:                         # ~ operator AuC/HSS holding the same K
    def __init__(self, K): self._K = K; self.used_rands = set()
    def challenge(self):
        rand = generate_rand()
        while rand in self.used_rands: rand = generate_rand()
        self.used_rands.add(rand)          # track used RANDs (Task 1)
        return rand, compute_autn(self._K, rand)
    def verify(self, rand, res):
        return hmac.compare_digest(compute_response(self._K, rand), res)
    def verify_with_replay_check(self, rand, res, seen):
        if rand in seen: return False      # replay of an already-consumed challenge
        ok = self.verify(rand, res)
        if ok: seen.add(rand)
        return ok
    def session_key(self, rand): return derive_session_key(self._K, rand)

class Attacker:                            # sees only what crossed the channel; has NO reference to K
    def __init__(self): self.captured = []
    def sniff(self, rand, res): self.captured.append((rand, res))
    def replay_old_response(self):         return self.captured[-1][1]
    def guess_K_by_inspection(self):       # naive: try treating observed values / simple strings as K
        rand, res = self.captured[-1]
        return [rand, res, b"password", b"\x00"*16, bytes(16)]

def hx(b): return b.hex()[:24] + "..."

# ---------- main run ----------
if __name__ == "__main__":
    K = secrets.token_bytes(32)            # shared secret; "provisioned" into both, never transmitted
    dev, net, atk = Device(K), HomeNetwork(K), Attacker()

    print("=== 1. Successful mutual authentication ===")
    rand, autn = net.challenge()
    print("[channel] RAND  :", hx(rand)); print("[channel] AUTN  :", hx(autn))
    res = dev.respond(rand, autn)
    print("[device ] network authenticated via AUTN -> computed RES")
    print("[channel] RES   :", hx(res)); atk.sniff(rand, res)
    ok = net.verify(rand, res)
    print("[network] RES matches XRES :", ok)
    ks_dev, ks_net = dev.session_key(rand), net.session_key(rand)
    print("[device ] session key :", hx(ks_dev))
    print("[network] session key :", hx(ks_net))
    print("Identical session keys derived independently:", hmac.compare_digest(ks_dev, ks_net))
    print("Session key / K ever sent on channel?       : False (only RAND, AUTN, RES crossed)")
    print("RES != session key (distinct outputs)       :", res != ks_dev)

    print("\n=== 2. Attacker with only (RAND, RES) tries to answer a NEW challenge ===")
    rand2, autn2 = net.challenge()
    expected = compute_response(K, rand2)  # ground truth, used only to score the attacker
    replayed = atk.replay_old_response()
    print("Replay old RES against RAND2 succeeds :", hmac.compare_digest(replayed, expected))
    guess_hits = [hmac.compare_digest(compute_response(g, rand2), expected) for g in atk.guess_K_by_inspection()]
    print("Guessing K by inspection (5 tries) succeeded:", any(guess_hits))
    brute = sum(hmac.compare_digest(compute_response(secrets.token_bytes(32), rand2), expected) for _ in range(20000))
    print("20,000 random 256-bit K guesses succeeded :", brute, "(search space 2^256)")
    print("Network verdict on forged response   :", net.verify(rand2, replayed))

    print("\n=== 3. Lab Task 1: replay protection (HomeNetwork tracks used RAND) ===")
    seen = set()
    r1, _ = net.challenge(); legit = dev.respond(r1)
    print("Legitimate attempt accepted        :", net.verify_with_replay_check(r1, legit, seen))
    print("Exact replay of (RAND, RES) rejected:", not net.verify_with_replay_check(r1, legit, seen))

    print("\n=== 4. Lab Task 3: fake network (IMSI-catcher style) cannot authenticate to device ===")
    rogue_rand = secrets.token_bytes(16)
    rogue_autn = hmac.new(secrets.token_bytes(32), b"AUTN" + rogue_rand, hashlib.sha256).digest()[:16]
    print("Device response to rogue network    :", dev.respond(rogue_rand, rogue_autn), "(None = aborted)")
    print("Device response to genuine network  :", "RES issued" if dev.respond(*net.challenge()) else "aborted")

    print("\n=== 5. Different run -> different RAND & session key, same logic ===")
    for i in range(3):
        r, a = net.challenge(); s = dev.session_key(r)
        print(f"run {i+1}: RAND={hx(r)} session_key={hx(s)} auth_ok={net.verify(r, dev.respond(r, a))}")
