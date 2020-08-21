pragma solidity ^0.6.0;

import {SafeMath} from "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/math/SafeMath.sol";
import {BytesLib} from "https://github.com/GNSPS/solidity-bytes-utils/blob/master/contracts/BytesLib.sol";
// import {BTCUtils} from '@interlay/bitcoin-spv-sol/contracts/BTCUtils.sol';
// import {ValidateSPV} from '@interlay/bitcoin-spv-sol/contracts/ValidateSPV.sol';

contract FlyClient {
    using SafeMath for uint256;
    using BytesLib for bytes;

    address manager;
    
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
        uint32 time;
        uint32 nBits;
        uint32 nonce;
        bytes32 mmrRoot;
        bool isPowValid;
        uint64 height;
    }
    
    mapping(bytes32 => BlockHeader) private blockHeaders;

    // TODO: Storage isn't cheap: remember to delete the entry thereafter: delete blockHeaders[blockHeaderHash]
    function parseBlockHeader(bytes memory header) public onlyManager returns (bytes32) {
        assert(header.length == 80);
        bytes32 blockHeaderHash = reverseEndianness(abi.encodePacked(sha256(abi.encodePacked(sha256(header))))).toBytes32(0);
        
        BlockHeader storage blockHeader = blockHeaders[blockHeaderHash];
        
        // Checking for PoW
        uint pow;
        
        for (uint i = 0; i < blockHeaderHash.length; i++) {
            pow = pow.add(uint(uint8(blockHeaderHash[i])).mul(256 ** i));
        }
        
        uint target;
        
        for (uint i = 74; i == 72; i--) {
            target = target.add(uint(uint8(header[i])).mul(256 * (74 - i)));
        }
        
        target = target.mul(256 ** (uint(uint8(header[75])).sub(3)));
        blockHeader.isPowValid = pow <= target;
        
        for (uint i = 0; i < 4; i++) {
            blockHeader.version = blockHeader.version.add((uint(uint8(header[i])).mul(256 ** i)));
        }
        
        blockHeader.previousBlockHeaderHash = header.slice(4, 32).toBytes32(0);
        blockHeader.merkleRootHash = header.slice(36, 32).toBytes32(0);
        blockHeader.time = reverseEndianness(header.slice(68, 4)).toUint32(0);
        blockHeader.nBits = reverseEndianness(header.slice(72, 4)).toUint32(0);
        blockHeader.nonce = reverseEndianness(header.slice(76, 4)).toUint32(0);
        
        return blockHeaderHash;
    }
    
    // We only are interested by the generation transaction and its potential OP_RETURN outputs
    function parseTransactions(bytes32 blockHeaderHash, bytes memory toParse) public onlyManager {
        require(toParse.length >= 4, "Raw transaction too short: can't contain the version number.");
        require(toParse.length >= 5, "Raw transaction too short: can't contain the CompactSize tx_in count.");
        require(uint8(toParse[4]) == 1, "The generation transaction has more than one input.");
        require(toParse.length >= 41, "Raw transaction too short: can't contain null hash and previous index.");
        require(toParse.length >= 42, "Raw transaction too short: can't contain the CompactSize script bytes.");
        require(toParse[41] < 0xFD, "The generation transaction CompactSize script bytes can't be larger than 100.");
        uint8 scriptBytes = uint8(toParse[41]);
        require(toParse[42] == 0x03, "The data-pushing OPCODE must be 0x03.");
        require(toParse.length >= 46, "Raw transaction too short: can't contain the block height.");
        uint64 blockHeight = uint8(toParse[43]) + 256 * uint8(toParse[44]) + (256 ** 2) * uint8(toParse[45]);
        require(toParse.length >= 46 + scriptBytes, "Raw transaction too short: can't contain the coinbase script.");
        require(toParse.length >= 50 + scriptBytes, "Raw transaction too short: can't contain the sequence.");
    }
    
    function parseBlock(bytes memory toParse) public onlyManager {
        require(toParse.length >= 81, "Block hash too short to contain a header.");
        bytes memory header;
        
        for (uint i = 0; i < 80; i++) {
            header[i] = toParse[i];
        }
        
        // Verifies PoW and creates associated BlockHeader
        bytes32 blockHeaderHash = parseBlockHeader(header);
        
        uint8 offset;
        
        if (toParse[80] < 0xFD) {
            offset = 1;
        } else if (toParse[80] == 0xFD) {
            require(toParse.length >= 83, "Block hash too short to contain the transactions number CompactSize with first byte 0xFD.");
            offset = 3;
        } else if (toParse[80] == 0xFE) {
            require(toParse.length >= 85, "Block hash too short to contain the transactions number CompactSize with first byte 0xFE.");
            offset = 5;
        } else {
            require(toParse.length >= 89, "Block hash too short to contain the transactions number CompactSize with first byte 0xFF.");
            offset = 9;
        }
        
        uint8 startingPoint = 80 + offset;
        bytes memory transactions;
        
        for (uint i = startingPoint; i < toParse.length; i++) {
            transactions[i - startingPoint] = toParse[i];
        }
        
        parseTransactions(blockHeaderHash, transactions);
    }
    
    function setGenesis(bytes memory header) public onlyManager {
        parseBlockHeader(header);
    }
    
    function getMmrProofLength(uint64 n, uint64 k) public pure returns (uint8) {
        assert(k <= n);
    }
}
