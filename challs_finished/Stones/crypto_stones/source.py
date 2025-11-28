import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG, SEED

random.seed(SEED)

# The monks' communion stones
stone_dict = {}
sealed_stones = []
with open("stones.txt", "w") as f:
    for i in range(2**20):
        sigil_a = random.getrandbits(128)
        sigil_b = random.getrandbits(128)
        stone_dict[sigil_a] = sigil_b
        echo = random.getrandbits(24)
        key = b"\x00"*12+echo.to_bytes(4)
        verse = f"Stone #{sigil_a}:{sigil_b}#".encode()
        cipher = AES.new(key, AES.MODE_ECB)
        seal = cipher.encrypt(pad(verse, 16)).hex()
        sealed_stones.append(seal)
        f.write(seal + "\n")

# One stone answers back
chosen = random.randint(0, 2**20)
chosen_stone = bytes.fromhex(sealed_stones[chosen].strip())

for echo in range(2**24):
    key = b"\x00"*12+echo.to_bytes(4)
    cipher = AES.new(key, AES.MODE_ECB)
    verse = cipher.decrypt(chosen_stone)
    if verse[:7] == b"Stone #":
        sigil_a = int(verse.split(b":")[0].split(b"#")[1])
        sigil_b = int(verse.split(b":")[1].split(b"#")[0])
        break

# Their resonance becomes the shared truth
assert stone_dict[sigil_a] == sigil_b

shared_echo = stone_dict[sigil_a]
key = shared_echo.to_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)
seal = cipher.encrypt(pad(FLAG, 16))

with open("oracle.txt", "w") as f:
    f.write(f"sigil_a = {sigil_a}\n")
    f.write(f"seal = {seal.hex()}\n")