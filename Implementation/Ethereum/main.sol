pragma solidity ^0.6.0;

import {SafeMath} from "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/math/SafeMath.sol";
import {BytesLib} from "https://github.com/GNSPS/solidity-bytes-utils/blob/master/contracts/BytesLib.sol";
// import {BTCUtils} from '@interlay/bitcoin-spv-sol/contracts/BTCUtils.sol';
// import {ValidateSPV} from '@interlay/bitcoin-spv-sol/contracts/ValidateSPV.sol';

// An implementation of FlyClient as a cross-chain relay. Note that this implementation assumes that FlyClient is deployed either as a hard or as a soft fork.
contract FlyClient {
    using SafeMath for uint256;
    using BytesLib for bytes;
    
    struct Commitment {
        uint64 chainLength;
        bytes32 mmrRoot;
        bytes32 headerHash;
        bytes32 txId;
    }
    
    mapping(address => Commitment) commitments;
    
    
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
    
    
    // TODO: We probably want the function to be external rather than public and the data location to be calldata rather than memory
    function verifyBlockHeader(bytes memory header) public pure returns (bool) {
        assert(header.length == 80);
        bytes32 blockHeaderHash = doubleSha256(header);
        
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
        
        if (pow > target) {
            return false;
        }

        // If the version needs to be checked, uncomment the following lines
        // uint version;
        
        // for (uint i = 0; i < 4; i++) {
        //     version = version.add((uint(uint8(header[i])).mul(256 ** i)));
        // }
        
        // if (version > 4) {
            // return false;
        // }
        
        // TODO: do we have to check the timestamp?
        return true;
    }
    
    function verifyProof(bytes32 id, bytes32 root, bytes memory proof, uint64 index) public pure returns (bool) {
        require(proof.length % 32 == 0, "The proof must be a concatenation of 32 bytes-long hashes.");
        bytes memory addedUpHashes;
        
        if (index % 2 == 0) {
            addedUpHashes = abi.encodePacked(sha256(proof.slice(0, 32).concat(abi.encodePacked(id))));
        } else {
            addedUpHashes = abi.encodePacked(sha256(abi.encodePacked(id).concat(proof.slice(0, 32))));
        }
        
        uint8 sliceBeginning = 32;
        index /= 2;
        
        while (sliceBeginning < proof.length) {
            if (index % 2 == 0) {
                addedUpHashes = abi.encodePacked(sha256(proof.slice(sliceBeginning, 32).concat(addedUpHashes)));
            } else {
                addedUpHashes = abi.encodePacked(sha256(addedUpHashes.concat(proof.slice(sliceBeginning, 32))));
            }
            sliceBeginning += 32;
            index /= 2;
        }
        
        return addedUpHashes.equal(abi.encodePacked(root));
    }

    
    function verifySubmittedBlock(bytes memory toParse, bytes memory merkleProof, bytes memory mmrProof, bytes32 mmrRoot) public pure returns (bool) {
        require(toParse.length >= 80, "Block hash too short to contain a header.");
        bytes memory header = toParse.slice(0, 80);
        
        // Verifies Block header (PoW, ...)
        if (!verifyBlockHeader(header)) {
            return false;
        }
        
        bytes memory generationTransaction;
        
        if (toParse[80] < 0xFD) {
            generationTransaction = toParse.slice(81, toParse.length - 81);
        } else if (toParse[80] == 0xFD) {
            require(toParse.length >= 83, "Block hash too short to contain the transactions number CompactSize with first byte 0xFD.");
            generationTransaction = toParse.slice(83, toParse.length - 83);
        } else if (toParse[80] == 0xFE) {
            require(toParse.length >= 85, "Block hash too short to contain the transactions number CompactSize with first byte 0xFE.");
            generationTransaction = toParse.slice(85, toParse.length - 85);
        } else {
            require(toParse.length >= 89, "Block hash too short to contain the transactions number CompactSize with first byte 0xFF.");
            generationTransaction = toParse.slice(89, toParse.length - 89);
        }
        
        // TODO: do we need to check for the validity of the outputs (ie do we have to check signatures)?
        // Check that the generation transaction is included within the block
        if (!verifyProof(doubleSha256(generationTransaction), reverseEndianness(header.slice(36, 32)).toBytes32(0), merkleProof, 0)) {
            return false;
        }
        
        require(generationTransaction.length >= 42, "Raw transaction too short: less than 42 bytes.");
        require(toParse[41] <= 0x64, "The generation transaction CompactSize script bytes can't be larger than 100");
        require(toParse.length >= 46 + uint8(toParse[41]), "Raw transaction too short: can't contain the coinbase script.");

        // Must be at least 32 bytes long + pattern
        require(uint8(toParse[41]) >= 37, "ScriptBytes too short to contain the MMR root and the pattern.");
        // MMR root must be included under the form "MMR(mmrRoot)", with "MMR(" and ")" being in ASCII, and mmrRoot being the mmrRoot in bytes in BE
        require(
            uint8(toParse[46]) == 0x4D && uint8(toParse[47]) == 0x4D && uint8(toParse[48]) == 0x52 && uint8(toParse[49]) == 0x28 && uint8(toParse[45 + uint8(toParse[41])]) == 0x29,
            "Pattern not found."
            );

        return verifyProof(
            doubleSha256(header),
            mmrRoot,
            mmrProof,
            uint8(toParse[43]) + 256 * uint8(toParse[44]) + (256 ** 2) * uint8(toParse[45])
        );
    }
    
    function commitment(
        bytes memory containsTx,
        bytes32 txId,
        bytes memory merkleProofTx,
        bytes memory merkleProofCoinbase,
        bytes memory mmrProof,
        uint64 chainLength,
        bytes memory lastHeader
    ) public {
        
    }
}
