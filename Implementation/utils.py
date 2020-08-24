from hashlib import sha256

import requests

def get_header_hash(header: str):
    """ Get the Bitcoin header hash.
    
    :param header: The header as an hexadecimal string
    """

    assert len(header) == 160
    return sha256(sha256(bytes.fromhex(header)).digest()).digest()[::-1].hex()

def get_target(header: str):
    """ Get the target from the header hash.

    :param header: The header as an hexadecimal string
    """
    assert len(header) == 80
    hb = bytes.fromhex(header)
    return int(hb[74:71:-1].hex(), 16) * pow(256, hb[75] - 3)

def get_block_by_hash_or_height(hash: str):
    r = requests.get(f"https://blockchain.info/rawblock/{hash}?format=hex")
    return r.text
