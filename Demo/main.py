import os

import solcx
from web3 import HTTPProvider, Web3

from create_chains import honest_hashes, honest_blocks, adversary_hashes, adversary_blocks, adversary_headers, honest_headers
from mmr import bitcoin_hash, Mmr

w3 = Web3(HTTPProvider("http://127.0.0.1:8545"))
solcx.set_solc_version_pragma("^0.6.0")
os.chdir("../Implementation/Ethereum")

with open("main.sol", "r") as f:
    compiled = solcx.compile_source(f.read())["<stdin>:FlyClient"]

os.chdir("../../Demo")

contract = w3.eth.contract(
        abi=compiled["abi"],
        address=w3.eth.getTransactionReceipt(w3.eth.getBlock(1)["transactions"][0]).contractAddress
)

adv_mmr = Mmr(adversary_hashes)
hon_mmr = Mmr(honest_hashes)

# With HEIGHT >= 101, provers disagree
HEIGHT = 101

containsTx = adversary_headers[HEIGHT - 1]
txId = adversary_blocks[HEIGHT - 1][35+32:35:-1]
merkleProof = b""
indexTx = 1
mmrProof = bytes.fromhex(adv_mmr.get_path(HEIGHT))
chainLength = adv_mmr.n
mmrRoot = adv_mmr.root
