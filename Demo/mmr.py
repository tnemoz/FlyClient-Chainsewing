from hashlib import sha256
from math import log2
import re
from typing import List, Optional, Union

def bitcoin_hash(to_hash: str) -> str:
    return sha256(sha256(bytes.fromhex(to_hash)).digest()).digest()[::-1].hex()

def is_power_of_2(x: int) -> bool:
    return bool(re.match("^0b10*$", bin(x)))

# Implemented according to the FlyClient paper
class Mmr:
    def __init__(self, hashes: List[str] = []):
        if not len(hashes):
            self.left: Optional[Mmr] = None
            self.right: Optional[Mmr] = None
            self.root: str = ""
        elif len(hashes) == 1:
            self.root: str = hashes[0]
            self.left: Optional[Mmr] = None
            self.right: Optional[Mmr] = None
        elif len(hashes) == 2:
            self.root: str = bitcoin_hash(hashes[0] + hashes[1])
            self.left: Optional[Mmr] = Mmr([hashes[0]])
            self.right: Optional[Mmr] = Mmr([hashes[1]])
        else:
            index = len(hashes) // 2 if is_power_of_2(len(hashes)) else pow(2, int(log2(len(hashes))))
            self.left: Optional[Mmr] = Mmr(hashes[:index])
            self.right: Optional[Mmr] = Mmr(hashes[index:])
            self.root: str = bitcoin_hash(self.left.root + self.right.root)
        
        self.leaves: List[str] = hashes[:]
        self.n: int = len(hashes)

    def __add__(self, value):
        if isinstance(value, str):
            if is_power_of_2(self.n):
                res = Mmr()
                res.left = Mmr(self.leaves)
                res.right = Mmr([value])
            else:
                res = Mmr(self.leaves)
                res.right += value
            
            res.root = bitcoin_hash(res.left.root + res.right.root)
            res.leaves = self.leaves + [value]
            res.n = self.n + 1

            return res
        try:
            iter(value)
        except TypeError:
            return NotImplemented

        temp = Mmr(self.leaves)

        for v in value:
            temp += v

        return temp

    def __iadd__(self, value):
        return self.__add__(value)

    def __sub__(self, value):
        if isinstance(value, str):
            if value not in self.leaves:
                raise ValueError(f"Hash {value} is not in the leaves of the MMR.")
            
            index = self.hashes.index(value)
            return Mmr(self.hashes[:index] + self.hashes[index + 1:])
        try:
            iter(value)
        except TypeError:
            return NotImplemented

        temp = Mmr(self.leaves)

        for v in values:
            temp -= v

        return temp

    def __isub__(self, value):
        return self.__sub__(value)

    def __repr__(self) -> str:
        if self.left is None:
            assert self.n <= 1
            return f"Leaf(value: {self.root})"
        return f"MMR(n: {self.n}, root: {self.root}, left: {self.left.root}, right: {self.right.value})"

    def __getitem__(self, key):
        return self.hashes.__getitem__(key)

    def __setitem__(self, key, value):
        self.hashes.__setitem__(key, value)
        self = Mmr(self.hashes)

    def __delitem__(self, key):
        self.hashes.__delitem__(key)
        self = Mmr(self.hashes)

    def __len__(self):
        return self.n
    
    def __bool__(self):
        return self.n > 0

    def get_path(self, h: Union[int, str]):
        if isinstance(h, str):
            if h not in self.leaves:
                raise ValueError(f"Hash {h} is not in the leaves of the MMR.")
            return self.get_path(self.hashes.index(h))
        pass

    def verify_proof(self, proof: str):
        pass
            
hashes = [bitcoin_hash(hex(x)[2:]) for x in range(16, 25)]
m = Mmr(hashes)

