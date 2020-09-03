pragma solidity ^0.6.0;

import {SafeMath} from "./SafeMath.sol";
import {BytesLib} from "./BytesLib.sol";

/// @title An implementation of FlyClient as a chain-relay resistant to chain-sewing attacks.
/// @author Tristan NEMOZ
/// @notice The goal is to verify that a transaction is included within the Bitcoin block chain while sending
/// only a logarithmic number of blocks regarding to the chain length. This implementation is inherently 
/// interactive and the protcol documentation is to be read to use it.
/// @dev A lot of optimisations can probably be done if this contract were to be applied on a real-world case.
contract FlyClient {
    using SafeMath for uint256;
    using BytesLib for bytes;
    
    uint8 public constant MAX_SAMPLING_SIZE = 16;
    
    modifier headerIs80BytesLong(bytes memory header) {
        require(header.length == 80, "Block header size different from 80 bytes.");
        _;
    }
    
    modifier noResultSet(bytes32 txId) {
        require(!hasResultBeenSet[txId], "A result already has been determined for this transaction.");
        _;
    }
    
    // Represents the commitment of a prover to their chain.
    struct Commitment {
        uint64 chainLength;
        bytes32 mmrRoot;
        bool txExists;
        uint64 height;
    }
    
    // Represents the sampled blocks that a prover has to provide.
    struct ChainState{
        bytes32[] hashes;
        bytes32[] previousHashes;
    }
    
    // Saves the provers index. Using indexes and arrays of size 2 is more convenient than using mappings of bytes32 to
    // mappings of address to something. This also add the possibility to delete data, since storage is not costly.
    mapping(bytes32 => address[2]) proversPositions;
    
    // Saves the commitments of both provers
    mapping(bytes32 => Commitment[2]) commitments;
    
    // Saves the block headers provided by both provers.
    mapping(bytes32 => ChainState[2]) chainsStates;
    
    // Saves whether every proof provided by both provers are valid.
    mapping(bytes32 => bool[2]) previousProofsValid;
    
    // Saves the number of blocks sampled during the first part of the protocol, when looking for the merging block.
    mapping(bytes32 => uint64) firstSamplingSize;
    
    // Saves whether the third part of the protocol, that is the random sampling, has to be started.
    mapping(bytes32 => bool) hasForkingBeenFound;
    
    // Saves the positions sampled by the client.
    mapping(bytes32 => uint64[]) positions;
    
    // Saves the result of the previous protocols, which allows to delete other mappings values
    mapping(bytes32 => bool) result;
    
    // Saves whether a protocol already ran for the given transaction.
    mapping(bytes32 => bool) hasResultBeenSet;
    
    // Saves whether the getNextSecond function has been called once
    mapping(bytes32 => bool) hasGetNextSecondBeenCalled;
    
    /// @author Tristan NEMOZ
    /// @notice Returns the index associated to a certain address. This index is used as an identifier to avoid
    /// using a mapping of bytes 32 to a mapping of address.
    /// @dev Using an enum may lead to cleaner/more legible code.
    /// @param txId The hash that identifies the transaction we're currently working with.
    /// @param sender The address to which the index is associated.
    /// @return The index associated to the index for the protocol associated to this transaction if this address
    /// is one of the provers, 2 otherwise.
    function getPosition(bytes32 txId, address sender) public view returns (uint8) {
        if (proversPositions[txId][0] == sender) {
            return 0;
        } else if (proversPositions[txId][1] == sender) {
            return 1;
        }
        // Address not in array
        return 2;
    }

    /// @author Tristan NEMOZ
    /// @notice Reverse the endianness of a given bytes object.
    /// @param toReverse The array whose endianness must be reversed.
    /// @return A new array identical to toReverse with endianness reversed.
    function reverseEndianness(bytes memory toReverse) public pure returns (bytes memory) {
        bytes memory res = new bytes(toReverse.length);

        for (uint i = 0; i < toReverse.length; i++) {
            res[toReverse.length - i - 1] = toReverse[i];
        }

        return res;
    }
    
    /// @author Tristan NEMOZ
    /// @notice Apply the hash function used by the Bitcoin protocol.
    /// @param toHash The bytes object whose hash must be computed.
    /// @return The hash of the given object as specified by the Bitcoin protocol.
    function doubleSha256(bytes memory toHash) public pure returns (bytes32) {
        return reverseEndianness(abi.encodePacked(sha256(abi.encodePacked(sha256(toHash))))).toBytes32(0);
    }
    
    
    // TODO: We probably want the function to be external rather than public and the data location to be calldata rather than memory
    /// @author Tristan NEMOZ
    /// @notice Checks that a given block header has a valid PoW
    /// @dev Do we want this function to be external with data location calldata? Do we want to check that the block is valid
    /// regarding to other issues of the Bitcoin protocol, such as the version number?
    /// @param header The header of the block to be verified.
    /// @return A boolean indicating whether the block header was valid.
    function verifyBlockHeader(bytes memory header) private pure returns (bool) {
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
        
        return true;
    }
    
    /// @author Tristan NEMOZ
    /// @notice Computes ceil(log2(x)).
    /// @dev There is surely a faster method by looking at the size x takes in memory in assembly.
    /// @param x The integer to compute the ceiled log2.
    /// @return res = ceil(log2(x)).
    function ceiledLog2(uint64 x) private pure returns (uint8 res) {
        assert(x >= 1);
        x -= 1;
        while (x > 0) {
            x /= 2;
            res += 1;
        }
    }
    
    /// @author Tristan NEMOZ
    /// @notice Verify a Merkle proof.
    /// @param txId The hash whose inclusion is to be verified.
    /// @param root The root of the Merkle Tree.
    /// @param proof The path along the Merkle Tree to prove the inclusion.
    /// @param index The index of the hash to be verified within the Merkle Tree.
    /// @return A boolean indicating whether the proof is valid.
    function verifyMerkleProof(bytes32 txId, bytes32 root, bytes memory proof, uint64 index) public pure returns (bool) {
        require(proof.length % 32 == 0, "The proof must be a concatenation of 32 bytes-long hashes.");
        
        if (proof.length == 0) {
            return txId == root;
        }
        
        bytes memory addedUpHashes;
        index -= 1;
        
        if (index % 2 == 0) {
            addedUpHashes = abi.encodePacked(sha256(abi.encodePacked(txId).concat(proof.slice(0, 32))));
        } else {
            addedUpHashes = abi.encodePacked(sha256(proof.slice(0, 32).concat(abi.encodePacked(txId))));
        }
        
        uint8 sliceBeginning = 32;
        index /= 2;
        
        while (sliceBeginning < proof.length) {
            if (index % 2 == 0) {
                addedUpHashes = abi.encodePacked(sha256(addedUpHashes.concat(proof.slice(sliceBeginning, 32))));
            } else {
                addedUpHashes = abi.encodePacked(sha256(proof.slice(sliceBeginning, 32).concat(addedUpHashes)));
            }
            sliceBeginning += 32;
            index /= 2;
        }
        
        return addedUpHashes.equal(abi.encodePacked(root));
    }
    
    /// @author Tristan NEMOZ
    /// @notice Verify a MMR proof.
    /// @param id The hash whose inclusion is to be verified.
    /// @param root The root of the MMR.
    /// @param proof The path along the MMR to prove the inclusion.
    /// @param index The index of the hash to be verified within the MMR.
    /// @param leavesNumber Number of leaves in the MMR.
    /// @return A boolean indicating whether the proof is valid.
    function verifyMmrProof(bytes32 id, bytes32 root, bytes memory proof, uint64 index, uint64 leavesNumber) private pure returns (bool) {
        require(proof.length % 32 == 0, "The proof must be a concatenation of 32 bytes-long hashes.");
        bytes memory addedUpHashes;
        index -= 1;
        uint64 n = leavesNumber - 1;
        
        if ((index % 2 == 0) && index + 1 <= leavesNumber) {
            addedUpHashes = abi.encodePacked(sha256(abi.encodePacked(id).concat(proof.slice(0, 32))));
        } else {
            addedUpHashes = abi.encodePacked(sha256(proof.slice(0, 32).concat(abi.encodePacked(id))));
        }
        
        uint8 sliceBeginning = 32;
        index /= 2;
        n /= 2;
        
        while (sliceBeginning < proof.length) {
            if ((index % 2 == 0) && (index + 1 <= n)) {
                addedUpHashes = abi.encodePacked(sha256(addedUpHashes.concat(proof.slice(sliceBeginning, 32))));
            } else {
                addedUpHashes = abi.encodePacked(sha256(proof.slice(sliceBeginning, 32).concat(addedUpHashes)));
            }
            sliceBeginning += 32;
            index /= 2;
        }
        
        return addedUpHashes.equal(abi.encodePacked(root));
    }
    
    /// @author Tristan NEMOZ
    /// @notice Wrapper function to check that a submitted block is valid according to the protocol rules.
    /// @param header The block header whose validity is to be verified.
    /// @param height The height of the block within the Bitcoin chain.
    /// @param mmrProof The MMR proof of inclusion of the block within the Bitcoin chain.
    /// @param mmrRoot The MMR root associated with the Bitcoin chain.
    function verifySubmittedBlock(bytes memory header, uint64 height, bytes memory mmrProof, bytes32 mmrRoot, uint64 chainLength) private pure headerIs80BytesLong(header) returns (bool) {
        return verifyBlockHeader(header) && verifyMmrProof(doubleSha256(header), mmrRoot, mmrProof, height, chainLength);
    }
    
    /// @author Tristan NEMOZ
    /// @notice Extracts the previous block header hash in correct endianness from a block header.
    /// @param header The block header whose previous block header hash must be extracted.
    /// @return The previous block header hash with correct endianness.
    function extractPreviousBlockHash(bytes memory header) private pure returns (bytes32) {
        return reverseEndianness(header.slice(4, 32)).toBytes32(0);
    }
    
    /// @author Tristan NEMOZ
    /// @notice Commits an address to its chain using the FlyClient protocol.
    /// @param containsTx The block header which supposedly contains the transaction to be verified.
    /// @param height The height of the block header that contains the transaction to be verified.
    /// @param txId The hash of the transaction to be verified.
    /// @param merkleProof The Merkle Proof of inclusion of the transaction within the submitted block header.
    /// If the prover thinks that this transaction is not included in the block at the requested height, this parameter
    /// is ignored.
    /// @param indexTx The index if the transaction within the block that contains it. If the prover thinks that
    /// the transaction isn't included in the block at the requested height, they have to pass 0 to this parameter.
    /// @param mmrProof The MMR proof of inclusion of the submitted block header within the Bitcoin blockchain.
    /// @param chainLength The length of the Bitcoin chain according to the prover. It has to be consistent with the
    /// provided MMR root.
    /// @param mmrRoot The MMR root associated with the prover's chain.
    /// @dev This implementation does not support more than 2 provers.
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
        require(!hasResultBeenSet[txId], "A result already has been determined for this transaction.");
        if (indexTx > 0) {
            require(
                verifyMerkleProof(txId, reverseEndianness(containsTx.slice(36, 32)).toBytes32(0), merkleProof, indexTx),
                "Couldn't verify the inclusion of the transaction within the block."
            );
        }
        bytes32 headerHash = doubleSha256(containsTx);
        require(
            verifyMmrProof(headerHash, mmrRoot, mmrProof, height, chainLength),
            "Couldn't verify the inclusion of the block within the chain."
        );
        
        uint8 index = getPosition(txId, msg.sender);
        // Ensuring a prover can't change their commit.
        require(index == 2, "This address already committed their chain.");
        require(
            (proversPositions[txId][0] == address(0)) || (proversPositions[txId][1] == address(0)),
            "Two provers already have committed their chain."
        );
        
        // Checking if the first idnex already has been assigned. If this is not the case, then proversPositions[txId][0] would
        // be equal to the default address value address(0).
        if (proversPositions[txId][0] == address(0)) {
            index = 0;
        } else {
            index = 1;
        }
        
        Commitment storage commit = commitments[txId][index];
        ChainState storage state = chainsStates[txId][index];
        // Saving index of the current user
        proversPositions[txId][index] = msg.sender;
        
        // Create the commit associated to this prover
        commit.chainLength = chainLength;
        commit.mmrRoot = mmrRoot;
        commit.txExists = indexTx > 0;
        commit.height = height;
        
        // Adding the provided block as a sampled one
        state.hashes.push(headerHash);
        state.previousHashes.push(extractPreviousBlockHash(containsTx));
        positions[txId].push(height);

        // Adding the next block to be sampled
        uint64 newPosition = height + ((chainLength - height + 1) / 2);
        positions[txId].push(newPosition);

        previousProofsValid[txId][index] = true;
    }
    
    /// @author Tristan NEMOZ
    /// @notice Checks whether both provers agree on the inclusion of the transaction within the chain.
    /// @param txId The hash of the transaction we're currently working with.
    /// @dev If there is no need to call cleanup, this function can be external view
    /// @return -1 if no second prover has been found yet, 1 if both provers agree, 0 otherwise.
    function verify(bytes32 txId) public noResultSet(txId) returns (int8) {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
        
        if (commitments[txId][1 - position].chainLength == 0) {
            return -1;
        }
        
        if (commitments[txId][0].txExists == commitments[txId][1].txExists) {
            hasResultBeenSet[txId] = true;
            result[txId] = commitments[txId][0].txExists;
            cleanup(txId);
            return 1;
        }
        
        return 0;
    }
    
    /// @author Tristan NEMOZ
    /// @notice Returns the result decided for a transaction whose existence has (not) been shown by the client.
    /// @param txId The hash of the transaction whose existence shall be verified.
    /// @return A boolean indicating whether the transaction existence has been shown.
    function getResult(bytes32 txId) external view returns (bool) {
        require(hasResultBeenSet[txId], "No result found for this transaction.");
        return result[txId];
    }
    
    /// @author Tristan NEMOZ
    /// @notice Provide the prover with the next block to provide the client with. It also indicates whether the protocol
    /// is over because a submitted proof was invalid or if the prover must call the getNextSecond function to proceed with
    /// the random sampling.
    /// @param txId The hash of the transaction we're currently working with.
    /// @return -1 if the other prover hasn't submitted their proofs yet, -2 if a proof that the caller submitted was invalid,
    /// -3 if a proof that the other prover submitted was invalid, -4 if the prover must call the getNextSecond function.
    function getNext(bytes32 txId) public returns (int72) {
        require(!hasResultBeenSet[txId], "A result already has been determined for this transaction.");
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
        ChainState storage state = chainsStates[txId][position];
        
        // If the prover hasn't submitted all their proofs, return the first block that they must provide.
        if (state.hashes.length < positions[txId].length) {
            return int72(positions[txId][state.hashes.length]);
        }
        
        // If at least one proof was invalid
        if (!previousProofsValid[txId][position]) {
            hasResultBeenSet[txId] = true;
            result[txId] = commitments[txId][1 - position].txExists;
            cleanup(txId);
            return -2;
        }
        
        // If at least one proof was invalid
        if (!previousProofsValid[txId][1 - position]) {
            hasResultBeenSet[txId] = true;
            result[txId] = commitments[txId][position].txExists;
            cleanup(txId);
            return -3;
        }
        
        if (chainsStates[txId][1 - position].hashes.length < positions[txId].length) {
            return -1;
        }
        
        Commitment storage commit = commitments[txId][position];
        
        // Since we want to compare the provers' proof, we need to sample blocks of the same height.
        uint64 commonChainLength;
        
        if (commit.chainLength < commitments[txId][1 - position].chainLength) {
            commonChainLength = commit.chainLength;
        } else {
            commonChainLength = commitments[txId][1 - position].chainLength;
        }
        
        uint64 step;
        
        // If we are trying to find the merging block
        if (firstSamplingSize[txId] == 0) {
            step = (commonChainLength - commit.height + 1) >> positions[txId].length;
        // If the merging block has not been found, we're looking for the forking block
        } else {
            step = commit.height >> (positions[txId].length - firstSamplingSize[txId]);
        }
        
        // During the Binary Search, both the last step and the one before can have a step of 1
        if (step == 0) {
            step = 1;
        }
        
        bool mustIncrease;
        
        // If we are trying to find the merging block
        if (firstSamplingSize[txId] == 0) {
            // If the hashes are different, then we went too far: we need to go back in the chain to find the merging block
            mustIncrease = state.hashes[state.hashes.length - 1] != chainsStates[txId][1 - position].hashes[state.hashes.length - 1];
        // If the merging block has not been found, we're looking for the forking block
        } else {
            // If the hashes are different, then we went too far: we need to go further in the chain to find the forking block
            mustIncrease = state.hashes[state.hashes.length - 1] == chainsStates[txId][1 - position].hashes[state.hashes.length - 1];
        }
        
        uint64 newPosition;
        
        if (mustIncrease) {
            // If positions[txId][positions[txId].length - 1] + step < commit.chainLength, then we stop the protocol by saying this block
            // has already been sampled
            newPosition = positions[txId][positions[txId].length - 1] + step;
        } else {
            // Not possible since by assumption both provers have the same genesis block.
            assert(positions[txId][positions[txId].length - 1] > step);
            newPosition = positions[txId][positions[txId].length - 1] - step;
        }
        
        
        bool hasAlreadyBeenSampled;
        
        for (uint i = 0; i < positions[txId].length; i++) {
            if (positions[txId][i] == newPosition) {
                hasAlreadyBeenSampled = true;
                break;
            }
        }
        
        // If the next block to be sampled is too big, then there is no merging block.
        hasAlreadyBeenSampled = hasAlreadyBeenSampled || (positions[txId][positions[txId].length - 1] + step >= commit.chainLength);
        
        if (!hasAlreadyBeenSampled || (hasAlreadyBeenSampled && (firstSamplingSize[txId] == 0))) {
            // We have to start looking for the forking block
            if (hasAlreadyBeenSampled) {
                newPosition = commit.height - (commit.height / 2);
            }

            positions[txId].push(newPosition);
            return int72(newPosition);
        } else if (hasGetNextSecondBeenCalled[txId]) {
            // No fake blocks found, but sampling is over. The protocol has to be done once again
            hasResultBeenSet[txId] = true;
            cleanup(txId);
            hasResultBeenSet[txId] = false;
            return -5;
        } else {
            hasForkingBeenFound[txId] = true;
            return -4;
        }
    }
    
    /// @author Tristan NEMOZ
    /// @notice Provide the prover with the blocks indexes that they must submit to the client to prove their fork is
    /// the main one.
    /// @param txId The hash of the transaction we're currently working with.
    /// @return The blocks indexes that the provers must provide the client with.
    /// @dev There's a probably more efficient way to sample uniformly.
    function getNextSecond(bytes32 txId) public noResultSet(txId) returns (uint64[] memory) {
        require(hasForkingBeenFound[txId], "Forking block hasn't been found yet.");
        hasGetNextSecondBeenCalled[txId] = true;
        uint64 forkingHeight = findForkingHeight(txId);
        uint64 commonChainLength;
        
        if (commitments[txId][0].chainLength <= commitments[txId][1].chainLength) {
            commonChainLength = commitments[txId][0].chainLength;
        } else {
            commonChainLength = commitments[txId][1].chainLength;
        }
        
        if (commonChainLength - forkingHeight - 1 <= MAX_SAMPLING_SIZE) {
            uint64[] memory sampled = new uint64[](commonChainLength - forkingHeight - 1);
            // We already have sampled the block with height forkingHeight, hence we don't consider it in the sampling
            for (uint64 i = forkingHeight + 1; i < commonChainLength; i++) {
                sampled[i - forkingHeight - 1] = i;
            }
            return sampled;
        }
        
        bytes32 previousEthereumBlockHash = blockhash(block.number - 1);
        uint64[] memory sampled = new uint64[](MAX_SAMPLING_SIZE);
        uint8 step = 32 / MAX_SAMPLING_SIZE;
        uint64 remainingHeights = commonChainLength - forkingHeight - 1;
        uint64[] memory possibleSampled = new uint64[](remainingHeights);
        uint maxValue = uint(256) ** step;
        
        for (uint64 i = forkingHeight + 1; i < commonChainLength; i++) {
            possibleSampled[i - forkingHeight - 1] = i;
        }
        
        for (uint8 i = 0; i < MAX_SAMPLING_SIZE; i++) {
            uint temp;
            
            for (uint j = 0; j < step; j++) {
                temp += uint8(previousEthereumBlockHash[step * i + j]) * (256 ** j);
            }
            
            uint sample = temp / (maxValue / remainingHeights);
            sampled[i] = possibleSampled[sample];
            remainingHeights -= 1;
            possibleSampled[sample] = possibleSampled[possibleSampled.length - 1];
            delete possibleSampled[possibleSampled.length - 1];
        }
        
        return sampled;
    }
    
    /// @author Tristan NEMOZ
    /// @notice Finds the last forking block of the chain associated to this transaction, that is the block with
    /// the largest height such that provers disagree on it but agree on its parent.
    /// @param txId The hash of the transaction we're currently working with.
    /// @return The height of the forking block with the largest height.
    function findForkingHeight(bytes32 txId) public view returns (uint64) {
        ChainState storage state = chainsStates[txId][0];
        ChainState storage otherState = chainsStates[txId][1];
        uint64 minHeight = positions[txId][0];
        uint64 previousHeight = positions[txId][0];
        uint64 previousHeightIndex = 0;
        
        for (uint64 i = 1; i < positions[txId].length; i++) {
            if (positions[txId][i] < minHeight) {
                minHeight = positions[txId][i];
            }
            
            if (positions[txId][i] > previousHeight) {
                previousHeight = positions[txId][i];
                previousHeightIndex = i;
            }
        }
        
        // bool arePreviousHashesEqual = state.hashes[previousHeight] == otherState.hashes[previousHeight];
        uint64 currentHeight;
        uint64 currentHeightIndex;
        
        for (uint64 i = 1; i < positions[txId].length; i++) {
            currentHeight = minHeight;
            
            // Looking starting from the end of the chain ensures we find the smallest possible fork. Note that
            // it implies that the forking point is not necessarily the one related to the transaction we're 
            // working with. However, since the prover is not supposed to have a fork anyway, and since the 
            // transaction won't be accepted if in doubt (see the else if (hasGetNextSecondBeenCalled[txId]) case
            // in the getNext function), we are fine doing it like this.
            for (uint64 j = 0; j < positions[txId].length; j++) {
                if ((positions[txId][j] > currentHeight) && (positions[txId][j] < previousHeight)) {
                    currentHeight = positions[txId][j];
                    currentHeightIndex = j;
                }
            }
            
            if (
                (currentHeight == previousHeight + 1) &&
                (state.hashes[previousHeightIndex] == otherState.hashes[previousHeightIndex]) &&
                (state.hashes[currentHeightIndex] != otherState.hashes[currentHeightIndex])
            ) {
                // The first block of the fork is at height currentHeight
                return currentHeight;
            } else {
                previousHeight = currentHeight;
                previousHeightIndex = currentHeightIndex;
            }
        }
        assert(false);
    }
    
    /// @author Tristan NEMOZ
    /// @notice Used to provide the client with the block header it asked for.
    /// @param txId The hash of the transaction we're currently working with.
    /// @param header The block header the client asked for.
    /// @param mmrProof The MMR proof of inclusion of the block header.
    function submitBlock(bytes32 txId, bytes memory header, bytes memory mmrProof) public noResultSet(txId) {
        uint8 position = getPosition(txId, msg.sender);
        require(position != 2, "Caller hasn't committed their chain yet.");
        uint64 height = positions[txId][chainsStates[txId][position].hashes.length];
        require(chainsStates[txId][position].hashes.length < positions[txId].length, "No block is to be submitted currently.");
        bool isBlockValid = verifySubmittedBlock(
            header,
            height,
            mmrProof,
            commitments[txId][position].mmrRoot,
            commitments[txId][position].chainLength
        );
        bytes32 headerHash = doubleSha256(header);
        bytes32 previousHash = extractPreviousBlockHash(header);
        
        for (uint i = 0; i < positions[txId].length; i++) {
            if (positions[txId][i] == height - 1) {
                isBlockValid = isBlockValid && chainsStates[txId][position].hashes[i] == extractPreviousBlockHash(header);
                break;
            } else if (positions[txId][i] == height + 1) {
                isBlockValid = isBlockValid && headerHash == chainsStates[txId][position].previousHashes[i];
                break;
            }
        }
        
        ChainState storage state = chainsStates[txId][position];
        state.hashes.push(headerHash);
        state.hashes.push(previousHash);
        
        // Ensuring that one non-valid proof stays non-valid after submitting other blocks.
        previousProofsValid[txId][position] = isBlockValid && previousProofsValid[txId][position];
    }
    
    /// @author Tristan NEMOZ
    /// @notice Deletes all remaining data once a proof is over.
    /// @param txId The hash of the transaction we were working with.
    function cleanup(bytes32 txId) private {
        require(hasResultBeenSet[txId], "No result has been found for this transaction.");
        delete proversPositions[txId];
        delete commitments[txId];
        delete chainsStates[txId];
        delete previousProofsValid[txId];
        delete firstSamplingSize[txId];
        delete hasForkingBeenFound[txId];
        delete positions[txId];
        delete hasGetNextSecondBeenCalled[txId];
    }
}
