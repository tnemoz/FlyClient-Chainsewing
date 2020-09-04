import os

import solcx
from web3 import HTTPProvider, Web3

from create_opened_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks
#from create_closed_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks
from mmr import bitcoin_hash, Mmr

class Node:
    def __init__(self, account, hashes, headers):
        self.account = account
        self.mmr = Mmr(hashes)
        self.headers = headers[:]
        self.next = 0

    def commit(self, height, txId, is_adversary):
        print(f"[TX {txId.hex()}][*] Account {self.account} is committing their chain...")
        containsTx = self.headers[height - 1]
        merkleProof = b""
        indexTx = 1 if is_adversary else 0
        mmrProof = bytes.fromhex(self.mmr.get_path(height))
        chainLength = self.mmr.n
        mmrRoot = bytes.fromhex(self.mmr.root)
        contract.functions.commitment(containsTx, height, txId, merkleProof, indexTx, mmrProof, chainLength, mmrRoot).transact({'from' : self.account})
        print("[TX {txId.hex()}][+] Account {self.account} has finished to commit their chain.")

    def submit_block(self, txId):
        assert self.next > 0, "Last return was a return code."
        print(f"[TX {txId.hex()}][*] Account {self.account} is submitting block at height {self.next}...")
        contract.functions.submitBlock(txId, self.headers[self.next - 1], bytes.fromhex(self.mmr.get_path(self.next))).transact({"from": self.account})
        print(f"[TX {txId.hex()}][+] Account {self.account} has submitted block at height {self.next}")

    def get_next(self, txId):
        print(f"[TX {txId.hex()}][*] Account {self.account} querying next block to sample...")
        receipt = w3.eth.waitForTransactionReceipt(contract.functions.getNext(txId).transact({"from": self.account}))
        # Easy to convert if positive number
        print("Received data:", receipt["logs"][0]['data'])
        data = int(receipt['logs'][0]['data'], 16)
        self.next = data if data < pow(2, 255) else data - pow(2, 256)

        if self.next == -2:
            print(f"[TX {txId.hex()}][-] Protocol is over for account {self.account}. One of the submitted proof was wrong.")
        elif self.next == -3:
            print(f"[TX {txId.hex()}][+] Protocol is over for account {self.account}. One of the other prover's submitted proof was wrong.")
        elif self.next == -1:
            print(f"[TX {txId.hex()}][*] The other prover hasn't submitted all their proofs yet..")
        

w3 = Web3(HTTPProvider("http://127.0.0.1:8545"))
w3.eth.defaultAccount = w3.eth.accounts[0]

solcx.set_solc_version_pragma("^0.6.0")
os.chdir("../Implementation/Ethereum")

with open("main.sol", "r") as f:
    compiled = solcx.compile_source(f.read())["<stdin>:FlyClient"]

os.chdir("../../Demo")

contract = w3.eth.contract(
    abi=compiled["abi"],
    bytecode=compiled["bin"]
)

tx_hash = contract.constructor().transact()
contract_address = w3.eth.waitForTransactionReceipt(tx_hash).contractAddress

contract = w3.eth.contract(
    abi=compiled["abi"],
    address=contract_address
)

# With HEIGHT >= 101, provers disagree
HEIGHT = 101
TXID = adversary_blocks[HEIGHT - 1][35+32:35:-1] 

adversary = Node(w3.eth.accounts[1], adversary_hashes, adversary_headers)
honest = Node(w3.eth.accounts[2], honest_hashes, honest_headers)

adversary.commit(HEIGHT, TXID, is_adversary=True)
honest.commit(HEIGHT, TXID, is_adversary=False)
