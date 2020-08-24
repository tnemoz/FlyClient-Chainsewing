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
    
    function doubleSha256(bytes memory toHash) public pure returns (bytes32) {
        return reverseEndianness(abi.encodePacked(sha256(abi.encodePacked(sha256(toHash))))).toBytes32(0);
    }
    
    struct BlockHeader {
        bytes32 previousBlockHeaderHash;
        bytes32 merkleRootHash;
        bytes32 mmrRoot;
        bool isPowValid;
        uint64 height;
    }
    
    mapping(bytes32 => BlockHeader) private blockHeaders;

    // TODO: Storage isn't cheap: remember to delete the entry thereafter: delete blockHeaders[blockHeaderHash]
    // TODO: We probably want the function to be external rather than public and the data location to be calldata rather than memory
    function parseBlockHeader(bytes memory header) public onlyManager returns (bytes32) {
        assert(header.length == 80);
        bytes32 blockHeaderHash = doubleSha256(header);
        
        BlockHeader storage blockHeader = blockHeaders[blockHeaderHash];
        
        // Checking for PoW
        // TODO: Use toUint32 function from ByteLib for a more efficient computation
        uint pow;
        
        for (uint i = 0; i < blockHeaderHash.length; i++) {
            pow = pow.add(uint(uint8(blockHeaderHash[i])).mul(256 ** i));
        }
        
        // TODO: Use toUint32 function from ByteLib for a more efficient computation
        uint target;
        
        for (uint i = 72; i == 74; i++) {
            target = target.add(uint(uint8(header[i])).mul(256 * (i - 72)));
        }
        
        target = target.mul(256 ** (uint(uint8(header[75])).sub(3)));
        // TODO: do we have to check the timestamp?
        blockHeader.isPowValid = pow <= target;
        
        // If the version needs to be checked, uncomment the following lines
        // uint version;
        
        // for (uint i = 0; i < 4; i++) {
        //     version = version.add((uint(uint8(header[i])).mul(256 ** i)));
        // }
        
        // require(version <= 4);
        
        blockHeader.previousBlockHeaderHash = reverseEndianness(header.slice(4, 32)).toBytes32(0);
        blockHeader.merkleRootHash = reverseEndianness(header.slice(36, 32)).toBytes32(0);

        return blockHeaderHash;
    }
    
    // We only are interested by the generation transaction and its coinbase attribute
    function parseTransactions(bytes32 blockHeaderHash, bytes memory toParse) public onlyManager returns (uint){
        require(toParse.length >= 42, "Raw transaction too short: less than 42 bytes.");
        // The generation transaction CompactSize script bytes can't be larger than 100
        assert(toParse[41] <= 0x64);
        uint8 scriptBytes = uint8(toParse[41]);
        require(toParse.length >= 46 + scriptBytes, "Raw transaction too short: can't contain the coinbase script.");
        BlockHeader storage blockHeader = blockHeaders[blockHeaderHash];
        blockHeader.height = uint8(toParse[43]) + 256 * uint8(toParse[44]) + (256 ** 2) * uint8(toParse[45]);
        bytes memory coinbase = toParse.slice(46, scriptBytes);
        
        // Must be at least 32 bytes long + pattern
        if (scriptBytes >= 37) {
            // If MMR root is included, it must be included under the form MMR(mmrRoot)
            if (uint8(coinbase[0]) == 0x4D && uint8(coinbase[1]) == 0x4D && uint8(coinbase[2]) == 0x52 && uint8(coinbase[3]) == 0x28 && uint8(coinbase[scriptBytes - 1]) == 0x29) {
                blockHeader.mmrRoot = coinbase.slice(4, 32).toBytes32(0);
            }
        }
    }
    
    
    function verifyTxInclusion(bytes32 txId, bytes32 headerHash, bytes memory merkleProof, uint64 index) public view returns (bool) {
        require(merkleProof.length % 32 == 0, "The Merkle Proof must be a concatenation of 32 bytes-long hashes.");
        bytes memory addedUpHashes;
        
        if (index % 2 == 0) {
            addedUpHashes = abi.encodePacked(sha256(merkleProof.slice(0, 32).concat(abi.encodePacked(txId))));
        } else {
            addedUpHashes = abi.encodePacked(sha256(abi.encodePacked(txId).concat(merkleProof.slice(0, 32))));
        }
        
        uint8 sliceBeginning = 32;
        index /= 2;
        
        while (sliceBeginning < merkleProof.length) {
            if (index % 2 == 0) {
                addedUpHashes = abi.encodePacked(sha256(merkleProof.slice(sliceBeginning, 32).concat(addedUpHashes)));
            } else {
                addedUpHashes = abi.encodePacked(sha256(addedUpHashes.concat(merkleProof.slice(sliceBeginning, 32))));
            }
            sliceBeginning += 32;
            index /= 2;
        }
        
        return addedUpHashes.equal(abi.encodePacked(blockHeaders[headerHash].merkleRootHash));
    }
    
    function verifySubmittedBlock(bytes memory toParse, bytes memory merkleProof) public onlyManager {
        require(toParse.length >= 80, "Block hash too short to contain a header.");
        bytes memory header = toParse.slice(0, 80);
        
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
        bytes memory generationTransaction = toParse.slice(startingPoint, toParse.length - startingPoint);
        parseTransactions(blockHeaderHash, generationTransaction);
        // TODO: do we need to check for the validity of the outputs (ie do we have to check signatures)?
        require(verifyTxInclusion(doubleSha256(generationTransaction), blockHeaderHash, merkleProof, 0), "The generation transaction isn't included within the block.");
    }
    
    function setGenesis(bytes memory header) public onlyManager {
        parseBlockHeader(header);
    }
    
    function getMmrProofLength(uint64 n, uint64 k) public pure returns (uint8) {
        assert(k <= n);
    }
}
