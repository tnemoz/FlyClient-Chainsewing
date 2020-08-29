pragma solidity ^0.6.0;

import {SafeMath} from "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/math/SafeMath.sol";
import {BytesLib} from "https://github.com/GNSPS/solidity-bytes-utils/blob/master/contracts/BytesLib.sol";


contract FlyClient {
    using SafeMath for uint256;
    using BytesLib for bytes;
    
    struct Commitment {
        uint64 chainLength;
        bytes32 mmrRoot;
        bool txExists;
        uint64 height;
    }
    
    struct ChainState{
        bytes32[] hashes;
        uint64[] positions;
    }
    
    mapping(bytes32 => address[2]) proversPositions;
    mapping(bytes32 => Commitment[2]) commitments;
    mapping(bytes32 => ChainState[2]) chainsStates;
    
    function getPosition(bytes32 txId, address sender) public view returns (uint8) {
        if (proversPositions[txId][0] == sender) {
            return 0;
        } else if (proversPositions[txId][0] == sender) {
            return 1;
        }
        // Address not in array, return error code
        return 2;
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
    
    function verifySubmittedBlock(bytes memory header, uint64 height, bytes memory mmrProof, bytes32 mmrRoot) public pure returns (bool) {
        require(header.length == 80, "Block header size different from 80 bytes.");
        return verifyBlockHeader(header) && verifyProof(doubleSha256(header), mmrRoot, mmrProof, height);
    }
    
    function commitment(
        bytes memory containsTx,
        uint64 height,
        bytes32 txId,
        bytes memory merkleProof,
        uint64 indexTx,
        bytes memory mmrProof,
        uint64 chainLength,
        bytes32 mmrRoot
    ) public {
        require(containsTx.length == 80, "Block header with size different from 80 bytes.");
        if (merkleProof.length > 0) {
            require(
                verifyProof(txId, reverseEndianness(containsTx.slice(36, 32)).toBytes32(0), merkleProof, indexTx),
                "Couldn't verify the inclusion of the transaction within the block."
            );
        }
        bytes32 headerHash = doubleSha256(containsTx);
        require(
            verifyProof(headerHash, mmrRoot, mmrProof, height),
            "Couldn't verify the inclusion of the block within the chain."
        );
        
        Commitment[2] storage commit = commitments[txId];
        address[2] storage provers = proversPositions[txId];
        ChainState[2] storage states = chainsStates[txId];
        // If hasn't commited yet or has commited and been assigned index 0, index=0. Otherwise, index=1
        uint8 index = getPosition(txId, msg.sender) % 2;
        provers[index] = msg.sender;
        commit[index].chainLength = chainLength;
        commit[index].mmrRoot = mmrRoot;
        commit[index].txExists = merkleProof.length > 0;
        commit[index].height = height;
        states[index].hashes.push(headerHash);
        states[index].positions.push(height);
    }
    
    function verify(bytes32 txId) public view returns (int8) {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
        
        if (commitments[txId][1 - position].chainLength == 0) {
            return -1;
        }
        
        if (commitments[txId][0].txExists == commitments[txId][1].txExists) {
            return 1;
        }
        
        return 0;
    }
    
    function getNext(bytes32 txId) public view returns (uint64) {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
    }
    
    function getNextSecond(bytes32 txId, uint64 forkLength) public view returns (uint64[] memory) {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
    }
    
    function submitBlock(bytes32 txId, bytes memory header, bytes memory mmrProof) public view {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
    }
}
