from enum import Enum
import os
from threading import Thread, Lock

import matplotlib.pyplot as plt
import numpy as np
import solcx
from termcolor import cprint
from web3 import HTTPProvider, Web3

CLOSED_FORKS = True

if CLOSED_FORKS:
    from create_closed_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks
else:
    from create_opened_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks

from mmr import bitcoin_hash, Mmr


class Level(Enum):
    NORMAL = 0
    ERROR = 1
    WARNING = 2
    SUCCESS = 3


class Node(Thread):
    def __init__(self, account, hashes, headers, height, txId, is_adversary, w3, contract, print_lock):
        self.account = account
        self.mmr = Mmr(hashes)
        self.headers = headers[:]
        self.gases = []
        self.next = 0
        self.w3 = w3
        self.print_lock = print_lock
        self.contract = contract
        self.txId = txId
        self.is_adversary = is_adversary
        self.is_waiting = False
        self.commit(height)
        super().__init__()

    def commit(self, height):
        self.print("Beginning to commit their chain...")
        containsTx = self.headers[height - 1]
        merkleProof = b""

        if CLOSED_FORKS:
            indexTx = 1 if (height <= 100 or height >= 111 or self.is_adversary) else 0
        else:
            indexTx = 1 if (height <= 100 or self.is_adversary) else 0

        mmrProof = bytes.fromhex(self.mmr.get_path(height))
        chainLength = self.mmr.n
        mmrRoot = bytes.fromhex(self.mmr.root)
        receipt = self.w3.eth.waitForTransactionReceipt(
            self.contract.functions.commitment(
                containsTx, 
                height,
                self.txId,
                merkleProof,
                indexTx,
                mmrProof,
                chainLength,
                mmrRoot
            ).transact({'from' : self.account})
        )
        self.gases.append(receipt.gasUsed)
        self.print("Chain commitement is done." , Level.SUCCESS)

    def submit_block(self):
        assert self.next > 0, "Last return was a return code."
        self.print(f"Submitting block at height {self.next}...")
        receipt = self.w3.eth.waitForTransactionReceipt(self.contract.functions.submitBlock(
            self.txId,
            self.headers[self.next - 1],
            bytes.fromhex(self.mmr.get_path(self.next))
        ).transact({"from": self.account}))
        self.gases.append(receipt.gasUsed)
        self.print(f"Submitted block at height {self.next}.", Level.SUCCESS)

    def get_next(self):
        self.print("Querying next block to sample...")
        receipt = self.w3.eth.waitForTransactionReceipt(
            self.contract.functions.getNext(self.txId).transact({"from": self.account})
        )
        # Easy to convert if positive number
        data = int(receipt['logs'][0]['data'], 16)
        self.next = data if data < pow(2, 255) else data - pow(2, 256)
        self.gases.append(receipt.gasUsed)

        if self.next == -2:
            self.print(f"Protocol is over: FAILURE", Level.ERROR)
        elif self.next == -3:
            self.print(f"Protocol is over: SUCCESS", Level.SUCCESS)
        elif self.next == -1 and not self.is_waiting:
            self.print(f"The other prover hasn't submitted all their proofs yet.", Level.WARNING)
            self.is_waiting = True
        elif self.next == -4:
            self.print(f"Protocol is over: couldn't determine which prover is the honest one.", Level.ERROR)
        else:
            self.print(f"Received next block to be sampled: {self.next}.", Level.SUCCESS)
            self.is_waiting = False
    
    def verify(self):
        self.print("Checking whether the other prover agrees.")
        try:
            receipt = self.w3.eth.waitForTransactionReceipt(
                self.contract.functions.verify(self.txId).transact({'from': self.account})
            )
        except ValueError as e:
            if "A result already has been determined for this transaction." in e.args[0]["message"]:
                return 1
            raise e
        
        self.gases.append(receipt.gasUsed)
        data = int(receipt['logs'][0]['data'], 16)
        data = data if data < pow(2, 255) else data - pow(2, 256)
        self.is_waiting = data != 0
        
        return data


    def print(self, message, level=Level.NORMAL):
        prefix = "Adversary" if self.is_adversary else "Honest   "

        if level == Level.NORMAL:
            to_print = f"[{prefix} INFO   ] {message}"
            color = None
        elif level == Level.ERROR:
            to_print = f"[{prefix} ERROR  ] {message}"
            color = "red"
        elif level == Level.WARNING:
            to_print = f"[{prefix} WARNING] {message}"
            color = "yellow"
        elif level == Level.SUCCESS:
            to_print = f"[{prefix} SUCCESS] {message}"
            color = "green"

        self.print_lock.acquire()
        cprint(to_print, color)
        self.print_lock.release()
    
    def run(self):
        # Waiting for other prover's commit
        while (verify := self.verify()) == -1:
            pass

        if verify == 1:
            self.print("Agreeing with the other prover on the transaction's inclusion.", Level.SUCCESS)
            return
        
        self.print("Don't agreeing with the other prover. Launching protocol.", Level.WARNING)

        while True:
            self.get_next()

            if self.next == -1:
                continue
            elif self.next < 0:
                return
            else:
                self.submit_block()

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
# In the case of a closed fork, for HEIGHT >= 110, even though the provers
# disagree on the MMR proof of inclusion of the block, they agree on the
# transaction. Hence, the protocol stops immediately.
HEIGHT = 105
TXID = adversary_blocks[HEIGHT - 1][35+32:35:-1] 

print_lock = Lock()

adversary = Node(
    w3.eth.accounts[1],
    adversary_hashes,
    adversary_headers, 
    HEIGHT,
    TXID,
    True,
    w3,
    contract,
    print_lock
)
honest = Node(
    w3.eth.accounts[2],
    honest_hashes,
    honest_headers,
    HEIGHT,
    TXID,
    False,
    w3,
    contract,
    print_lock
)

adversary.start()
honest.start()

adversary.join()
honest.join()

plt.figure()
plt.plot(np.linspace(0, 1, len(adversary.gases)), np.cumsum(adversary.gases), label="Adversary")
plt.plot(np.linspace(0, 1, len(honest.gases)), np.cumsum(honest.gases), label="Honest")
plt.legend()
plt.show()
