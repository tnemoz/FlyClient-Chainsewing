from enum import Enum
import os
from threading import Thread, Lock

import solcx
from termcolor import cprint
from web3 import HTTPProvider, Web3

#from create_opened_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks
from create_closed_fork_chains import honest_hashes, adversary_hashes, adversary_headers, honest_headers, adversary_blocks
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
        indexTx = 1 if self.is_adversary else 0
        mmrProof = bytes.fromhex(self.mmr.get_path(height))
        chainLength = self.mmr.n
        mmrRoot = bytes.fromhex(self.mmr.root)
        self.w3.eth.waitForTransactionReceipt(
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
        self.print("Chain commitement is done.", Level.SUCCESS)

    def submit_block(self):
        assert self.next > 0, "Last return was a return code."
        self.print(f"Submitting block at height {self.next}...")
        contract.functions.submitBlock(
            self.txId,
            self.headers[self.next - 1],
            bytes.fromhex(self.mmr.get_path(self.next))
        ).transact({"from": self.account})
        self.print(f"Submitted block at height {self.next}.", Level.SUCCESS)

    def get_next(self):
        self.print("Querying next block to sample...")
        receipt = w3.eth.waitForTransactionReceipt(
            contract.functions.getNext(self.txId).transact({"from": self.account})
        )
        # Easy to convert if positive number
        self.print(f"Received data from getNext: {receipt['logs'][0]['data']}.")
        data = int(receipt['logs'][0]['data'], 16)
        self.next = data if data < pow(2, 255) else data - pow(2, 256)

        if self.next == -2:
            self.print("Protocol is over: one of the submitted proof was wrong.", Level.ERROR)
        elif self.next == -3:
            self.print("Protocol is over: one of the other prover's submitted proof was wrong.", Level.SUCCESS)
        elif self.next == -1 and not self.is_waiting:
            self.print("The other prover hasn't submitted all their proofs yet.", Level.WARNING)
            self.is_waiting = True
        elif self.next == -4:
            self.print("Protocol is over: coudl'tn determine which prover is the honest one.", Level.ERROR)
        else:
            self.print(f"Received next block to be sampled: {self.next}.", Level.SUCCESS)
            self.is_waiting = False
    
    def print(self, message, level=Level.NORMAL):
        prefix = "Adversary" if self.is_adversary else "Honest"

        if level == Level.NORMAL:
            to_print = f"[{prefix} ] {message}"
            color = None
        elif level == Level.ERROR:
            to_print = f"[{prefix} -] {message}"
            color = "red"
        elif level == Level.WARNING:
            to_print = f"[{prefix} *] {message}"
            color = "yellow"
        elif level == Level.SUCCESS:
            to_print = f"[{prefix} +] {message}"
            color = "green"

        self.print_lock.acquire()
        cprint(to_print, color)
        self.print_lock.release()
    
    def run(self):
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
HEIGHT = 101
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
