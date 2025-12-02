// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Multisig
 * @notice Generic 3-of-5 EIP-712 multisig helper for admin operations.
 * @dev
 * - This module encapsulates signer configuration and signature validation
 *   for a fixed 3-of-5 multisig scheme.
 * - A contract that inherits this module is expected to:
 *   - Call the constructor with exactly 5 distinct, non-zero signer addresses.
 *   - Implement `_hashTyped` to bind EIP-712 typed data to its own domain
 *     (e.g. via OpenZeppelin EIP712 / ERC20Permit).
 *   - Use the predefined typehash constants and `_validateSigs` to protect
 *     privileged admin operations (pause, mint, lock, blacklist, etc.).
 */
abstract contract Multisig {
    address[5] private _msSigners;
    mapping(address => bool) private _isMsSigner;
    uint8 private _msThreshold;
    uint256 internal _msNonce;

    /// @dev EIP-712 typehashes for admin operations (shared by multisig children).
    bytes32 internal constant MS_PAUSE_TYPEHASH =
        keccak256("Pause(uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_UNPAUSE_TYPEHASH =
        keccak256("Unpause(uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_MINT_TYPEHASH =
        keccak256("Mint(uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_BURN_TYPEHASH =
        keccak256("Burn(uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_LOCK_FOR_TYPEHASH =
        keccak256("LockFor(address who,uint256 duration,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_LOCK_UNTIL_TYPEHASH =
        keccak256("LockUntil(address who,uint256 until,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_UNLOCK_TYPEHASH =
        keccak256("Unlock(address who,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_PRUNE_LOCKS_TYPEHASH =
        keccak256("PruneLocks(uint256 max,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_CFG_SIGNERS_TYPEHASH =
        keccak256("ReconfigureSigners(address[5] msSigners,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_SET_DEPLOYER_TYPEHASH =
        keccak256("SetDeployer(address newDeployer,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_RESCUE_TYPEHASH =
        keccak256("RescueERC20(address token,address to,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_ADD_BLACK_TYPEHASH =
        keccak256("AddBlacklist(address account,uint256 nonce,uint256 deadline)");
    bytes32 internal constant MS_REMOVE_BLACK_TYPEHASH =
        keccak256("RemoveBlacklist(address account,uint256 nonce,uint256 deadline)");

    /**
     * @notice Initializes the multisig with a fixed set of 5 signers.
     * @param signers The 5 distinct, non-zero multisig signer addresses.
     * @dev
     * - Reverts if any signer is the zero address.
     * - Reverts if there are duplicate signers.
     * - Threshold is fixed to 3-of-5.
     */
    constructor(address[5] memory signers) {
        _configureMultiSig(signers);
    }

    /**
     * @notice Returns the current multisig threshold.
     * @dev Always 3 in the current implementation.
     * @return The number of signatures required for a valid multisig operation.
     */
    function msThreshold() external view returns (uint8) {
        return _msThreshold;
    }

    /**
     * @notice Returns the current multisig nonce.
     * @dev Incremented by `_validateSigs` on every successful operation.
     * @return The latest consumed nonce value.
     */
    function msNonce() external view returns (uint256) {
        return _msNonce;
    }

    /**
     * @notice Internal configuration logic used by the constructor.
     *         Requires exactly 5 distinct non-zero signers.
     */
    function _configureMultiSig(address[5] memory signers) internal {
        for (uint256 i = 0; i < 5; i++) {
            if (_msSigners[i] != address(0)) {
                _isMsSigner[_msSigners[i]] = false;
            }
        }
        for (uint256 i = 0; i < 5; i++) {
            address s = signers[i];
            require(s != address(0), "MS: zero signer");
            require(!_isMsSigner[s], "MS: duplicate signer");
            _isMsSigner[s] = true;
            _msSigners[i] = s;
        }
        _msThreshold = 3;
    }

    /**
     * @notice Child must implement EIP-712 domain hashing.
     * @param structHash The EIP-712 struct hash for a specific admin operation.
     * @return The full EIP-712 digest bound to the child's domain.
     */
    function _hashTyped(bytes32 structHash) internal view virtual returns (bytes32);

    /**
     * @notice Validates EIP-712 signatures (3-of-5) for a given struct hash and deadline.
     * @param structHash The EIP-712 struct hash representing the admin action.
     * @param deadline Unix timestamp after which the signatures are considered expired.
     * @param sigs Array of 65-byte concatenated signatures (r, s, v) provided by signers.
     *
     * Requirements:
     * - Current block timestamp must be <= `deadline`.
     * - Threshold must be exactly 3.
     * - Each signature must be 65 bytes and recover to a configured signer.
     * - At least 3 distinct valid signer addresses must be recovered.
     *
     * Effects:
     * - Increments `_msNonce` on success.
     */
    function _validateSigs(bytes32 structHash, uint256 deadline, bytes[] calldata sigs) internal {
        require(block.timestamp <= deadline, "MS: expired");
        require(_msThreshold == 3, "MS: threshold");

        bytes32 digest = _hashTyped(structHash);

        uint256 valid;
        address[5] memory recoveredList;
        for (uint256 i = 0; i < sigs.length && valid < 5; i++) {
            bytes memory signature = sigs[i];
            require(signature.length == 65, "MS: bad sig");
            address rec = ECDSA.recover(digest, signature);
            if (!_isMsSigner[rec]) {
                continue;
            }
            bool dup = false;
            for (uint256 j = 0; j < valid; j++) {
                if (recoveredList[j] == rec) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                continue;
            }
            recoveredList[valid] = rec;
            valid++;
        }
        require(valid >= _msThreshold, "MS: not enough sigs");
        _msNonce++;
    }
}


