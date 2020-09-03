import os
import subprocess

check_bitcoind = subprocess.run(["ps", "-A"], capture_output=True)

for line in check_bitcoind.stdout.decode().splitlines()[1:]:
    if "bitcoind" in line:
        print("[*] Found process bitcoind. Continuing...")
        break
else:
    raise RuntimeError("bitcoin daemon is not running.")

honest_hashes_command = subprocess.run(
    [
        "bitcoin-cli", 
        "-regtest", 
        "generatetoaddress", 
        "201", 
        subprocess.run(
            ["bitcoin-cli", "-regtest", "getnewaddress"], 
        capture_output=True
        ).stdout.decode().split()[0]
    ], 
    capture_output=True
)

assert not honest_hashes_command.stderr, f"Error when creating honest hashes: {honest_hashes_command.stderr.decode()}."

honest_hashes = [h.split("\"")[1] for h in honest_hashes_command.stdout.decode().splitlines()[1:-1]]
honest_blocks = [
    subprocess.run(
        ["bitcoin-cli", "-regtest", "getblock", h, "0"], 
        capture_output=True
    ).stdout.decode().split()[-1] 
for h in honest_hashes]

honest_hashes = [
    subprocess.run(
        ["bitcoin-cli", "-regtest", "getblockhash", "0"], 
        capture_output=True
    ).stdout.decode().split()[0]
] + honest_hashes

honest_blocks = [
    subprocess.run(
        ["bitcoin-cli", "-regtest", "getblock", honest_hashes[0], "0"], 
        capture_output=True
    ).stdout.decode().split()[0]
] + honest_blocks

subprocess.run(["bitcoin-cli", "-regtest", "invalidateblock", honest_hashes[100]])

adversary_hashes_command = subprocess.run(
    [
        "bitcoin-cli", 
        "-regtest", 
        "generatetoaddress", 
        "10", 
        subprocess.run(
            ["bitcoin-cli", "-regtest", "getnewaddress"], 
        capture_output=True
        ).stdout.decode().split()[0]
    ], 
    capture_output=True
)

assert not adversary_hashes_command.stderr, f"Error when creating adversary hashes: {adversary_hashes_command.stderr.decode()}."

adversary_hashes = [h.split("\"")[1] for h in adversary_hashes_command.stdout.decode().splitlines()[1:-1]]
adversary_blocks = [
    subprocess.run(
        ["bitcoin-cli", "-regtest", "getblock", h, "0"], 
        capture_output=True
    ).stdout.decode().split()[-1] 
for h in adversary_hashes]
adversary_hashes = honest_hashes[:100] + adversary_hashes + honest_hashes[100 + len(adversary_hashes):]
adversary_blocks = honest_blocks[:100] + adversary_blocks + honest_blocks[100 + len(adversary_blocks):]

assert len(adversary_hashes) == len(adversary_blocks)
assert len(adversary_hashes) == len(honest_hashes)

adversary_blocks = [bytes.fromhex(h) for h in adversary_blocks]
honest_blocks = [bytes.fromhex(h) for h in honest_blocks]
adversary_headers = [h[:80] for h in adversary_blocks]
honest_headers = [h[:80] for h in honest_blocks]
