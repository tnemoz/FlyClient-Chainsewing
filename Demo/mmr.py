from hashlib import sha256
from math import ceil, log2
import re
from typing import List, Optional, Union

def bitcoin_hash(to_hash: str) -> str:
    return sha256(sha256(bytes.fromhex(to_hash)).digest()).digest()[::-1].hex()

def is_power_of_2(x: int) -> bool:
    return bool(re.match("^0b10*$", bin(x)))

# Implemented accordingly to the FlyClient paper
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
            
            index = self.leaves.index(value)
            return Mmr(self.leaves[:index] + self.leaves[index + 1:])
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
        return f"MMR(n: {self.n}, root: {self.root}, left: {self.left.root}, right: {self.right.root})"

    def __getitem__(self, key):
        if key == 0:
            raise IndexError("Can't index an MMR with 0.")
        
        key = key if key < 0 else key - 1
        
        return self.leaves.__getitem__(key)

    def __setitem__(self, key, value):
        if key == 0:
            raise IndexError("Can't index an MMR with 0.")
        
        key = key if key < 0 else key - 1
        self.leaves.__setitem__(key, value)
        self = Mmr(self.leaves)

    def __delitem__(self, key):
        if key == 0:
            raise IndexError("Can't index an MMR with 0.")
        
        key = key if key < 0 else key - 1

        self.leaves.__delitem__(key)
        self = Mmr(self.leaves)

    def __len__(self):
        return self.n
    
    def __bool__(self):
        return self.n > 0

    def __contains__(self, value):
        return self.leaves.__contains__(value)

    def index(self, value):
        return self.leaves.index(value) + 1
    
    # Correcting error in the FlyClient original paper. The proof size isn't
    # always equal to ceil(log2(n)) (it's only an upper bound).
    def get_path_size(self, h: Union[int, str]) -> int:
        if isinstance(h, str):
            if h not in self:
                raise ValueError(f"Hash {h} is not in the leaves of the MMR.")
            return self.get_path(self.index(h))
        if not isinstance(h, int):
            raise TypeError(f"Type not supported for indexing: {type(h)}.")
        
        def get_path_size_aux(m: Mmr, k: int) -> int:
            if m.n == 1:
                return 0
            if k <= m.left.n:
                return ceil(log2(m.n))
            return 1 + get_path_size_aux(m.right, k - m.left.n)

        return get_path_size_aux(self, self.index(self[h]))

    # Implemented accordingly to the FlyClient original paper
    def get_path(self, h: Union[int, str]) -> str:
        if self.n == 1:
            return ""
        if isinstance(h, str):
            if h not in self:
                raise ValueError(f"Hash {h} is not in the leaves of the MMR.")
            return self.get_path(self.index(h))
        if not isinstance(h, int):
            raise TypeError(f"Type not supported for indexing: {type(h)}.")
        
        h = self.index(self[h])

        if h <= self.left.n:
            return self.left.get_path(h) + self.right.root

        return self.right.get_path(h - self.left.n) + self.left.root
    
    # Implemented accordingly to the FlyClient original paper
    def verify_proof(self, h: Union[int, str], proof: str) -> bool:
        if isinstance(h, str):
            if h not in self.leaves:
                raise ValueError("Hash {h} is not in the leaves of the MMR.")
            return self.verify_proof(self.index(h), proof)
        if not isinstance(h, int):
            raise TypeError(f"Type not supported for indexing: {type(h)}.")
        if not isinstance(proof, str):
            raise TypeError(f"Type not supported for proof: {type(proof)}.")
        
        hashes = [proof[64*i:64*(i + 1)] for i in range(len(proof) // 64)]
        
        if len(hashes) != self.get_path_size(h):
            return False

        element = self[h]
        h = self.index(element) - 1
        n = self.n - 1
        
        for sibling in hashes:
            if h % 2 == 0 and h + 1 <= n:
                element = bitcoin_hash(element + sibling)
            else:
                element = bitcoin_hash(sibling + element)
            
            h //= 2
            n //= 2
        
        return element == self.root

