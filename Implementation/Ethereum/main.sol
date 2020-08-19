pragma solidity >=^0.5.11 < 0.6.0;

contract FlyClient {
    modifier onlyManager() {
        require(msg.sender == manager, "Access restricted function.");
        _;
    }
    
    constructor() public {
        manager = msg.sender;
    }


    function reverseEndianness(bytes memory toReverse) public pure returns (bytes memory) {
        bytes memory res = new bytes(toReverse.length);
        
        for (uint i = 0; i < toReverse.length; i++) {
            res[toReverse.length - i - 1] = toReverse[i];
        }
        
        return res;
    }
    
    struct BlockHeader {
        uint version;
        bytes32 previousBlockHeaderHash;
        bytes32 merkleRootHash;
        uint time;
        uint nBits;
        uint nonce;
        bytes32 mmrRoot;
        bool isPowValid;
    }
    
    mapping(bytes32 => BlockHeader) private blockHeaders;

    // TODO: Storage isn't cheap: remember to delete the entry thereafter: delete blockHeaders[blockHeaderHash]
    function parseBlockHeader(bytes memory header) public onlyManager {
        assert(header.length == 80, "parseBlockHeader called with an input whose length is different from 80.");
        bytes32 blockHeaderHash = reverseEndianness(sha256(sha256(header)));
        
        BlockHeader storage blockHeader = blockHeaders[blockHeaderHash];
        
        // Checking for PoW
        uint pow;
        
        for (uint i = 0; i < blockHeaderHash.length; i++) {
            pow += blockHeaderHash[i] * (256 ** i);
        }
        
        uint target;
        
        for (i = 74; i = 72; i--) {
            target += blockHeader[i] * (256 * (74 - i));
        }
        
        target *= 256 ** (blockHeader[75] - 3);
        blockHeader.isPowValid = pow <= target;
        
        for (i = 0; i < 4; i++) {
            blockHeader.version += (header[i] * (256 ** i));
        }
        
        for (; i < 36; i++) {
            blockHeader.previousBlockHeaderHash[i - 4] = header[i];
        }
        
        for (; i < 68; i++) {
            blockHeader.merkleRootHash[i - 36] = header[i];
        }
        
        for (; i < 72; i++) {
            blockHeader.time += (header[i] * (256 ** (i - 68)));
        }
        
        for (; i < 76; i++) {
            blockHeader.nBits += (header[i] * (256 ** (i - 72)));
        }
        
        for (; i < 80; i++) {
            blockHeader.nBits += (header[i] * (256 ** (i - 76)));
        }
    }
    
    // We only are interested by the generation transaction and their potential OP_RETURN outputs
    function parseTransactions(bytes memory transactions) public onlyManager {
        
    }
    
    function parseBlock(bytes memory toParse) public onlyManager {
        require(toParse.length >= 81, "Block hash too short to contain a header.");
        bytes memory header;
        
        for (uint i = 0; i < 80; i++) {
            header[i] = toParse[i];
        }
        
        // Verifies PoW and creates associated BlockHeader
        parseBlockHeader(header);
        
        uint8 offset;
        
        if (toParse[80] < 0xFD) {
            offset = 1;
        } else if (toParse[80] == 0xFD) {
            require(toParse.length >= 83, "Block hash too short to contain the transactions number varint with first byte 0xFD.");
            offset = 3;
        } else if (toParse[80] == 0xFE) {
            require(toParse.length >= 85, "Block hash too short to contain the transactions number varint with first byte 0xFE.");
            offset = 5;
        } else {
            require(toParse.length >= 89, "Block hash too short to contain the transactions number varint with first byte 0xFF.");
            offset = 9;
        }
        
        uint8 startingPoint = 80 + offset;
        bytes memory transactions;
        
        for (i = startingPoint; i < toParse.length; i++) {
            transactions[i - startingPoint] = toParse[i];
        }
        
        parseTransactions(transactions);
    }
    
    function setGenesis(bytes memory header) public onlyManager {
        parseBlockHeader(header);
    }
    
    function getMmrProofLength(uint64 n, uint64 k) public pure returns (uint8) {
        assert(k <= n);
    }
}
