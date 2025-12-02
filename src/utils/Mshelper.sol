// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Blacklist} from "src/utils/Blacklist.sol";
import {Lockable} from "src/utils/Lockable.sol";
import {Multisig} from "src/utils/Multisig.sol";

/**
 * @title Mshelper
 * @notice Multisig-protected admin wrapper layer for Switch-like ERC20 tokens.
 * @dev
 * - This module wires together:
 *   - `Multisig` (3-of-5 EIP-712 multisig validation),
 *   - `Pausable`, `Blacklist`, and `Lockable` admin hooks,
 *   - `ERC20Permit`'s EIP-712 domain for `_hashTyped`.
 * - A token that inherits this contract is expected to:
 *   - Call the `Mshelper` constructor with the 5 multisig signer addresses.
 *   - Set `_deployer` (the account that receives mint/burn admin operations).
 * - External admin functions in this module (pause, mint, lock, blacklist, etc.)
 *   perform:
 *   - EIP-712 multisig validation via `_msAuth*` helpers, then
 *   - Delegate to the underlying pause/lock/blacklist primitives.
 */
abstract contract Mshelper is ERC20Permit, Pausable, Blacklist, Lockable, Multisig, ReentrancyGuard {
    using SafeERC20 for IERC20;
    address internal _deployer;

    /**
     * @notice Initializes the multisig signer set for admin operations.
     * @param msSigners The 5 distinct, non-zero multisig signer addresses.
     */
    constructor(address[5] memory msSigners) Multisig(msSigners) {}

    /// @dev Wires EIP-712 hashing for the multisig base class.
    function _hashTyped(bytes32 structHash) internal view override returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /// @dev Inline-assembly helpers for computing keccak256 over tightly packed words.
    function _hash3(bytes32 typehash, uint256 a, uint256 b) private pure returns (bytes32 h) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), a)
            mstore(add(ptr, 0x40), b)
            h := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60))
        }
    }

    function _hash4(bytes32 typehash, uint256 a, uint256 b, uint256 c) private pure returns (bytes32 h) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), a)
            mstore(add(ptr, 0x40), b)
            mstore(add(ptr, 0x60), c)
            h := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
    }

    function _hash5(bytes32 typehash, uint256 a, uint256 b, uint256 c, uint256 d) private pure returns (bytes32 h) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), a)
            mstore(add(ptr, 0x40), b)
            mstore(add(ptr, 0x60), c)
            mstore(add(ptr, 0x80), d)
            h := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
    }

    function _hash6(bytes32 typehash, uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) private pure returns (bytes32 h) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), a)
            mstore(add(ptr, 0x40), b)
            mstore(add(ptr, 0x60), c)
            mstore(add(ptr, 0x80), d)
            mstore(add(ptr, 0xa0), e)
            h := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
    }

    /**
     * @dev Validates a multisig operation with no extra value parameter
     */
    function _msAuthSimple(bytes32 typehash, uint256 deadline, bytes[] calldata sigs) internal {
        bytes32 structHash = _hash3(typehash, _msNonce, deadline);
        _validateSigs(structHash, deadline, sigs);
    }

    /**
     * @dev Validates a multisig operation with a single uint256 parameter
     */
    function _msAuthUint(bytes32 typehash, uint256 value, uint256 deadline, bytes[] calldata sigs) internal {
        bytes32 structHash = _hash4(typehash, value, _msNonce, deadline);
        _validateSigs(structHash, deadline, sigs);
    }

    /**
     * @dev Validates a multisig operation with an address parameter
     */
    function _msAuthAddr(bytes32 typehash, address who, uint256 deadline, bytes[] calldata sigs) internal {
        bytes32 structHash = _hash4(typehash, uint256(uint160(who)), _msNonce, deadline);
        _validateSigs(structHash, deadline, sigs);
    }

    /**
     * @dev Validates a multisig operation with both address and uint256 parameters
     */
    function _msAuthAddrUint(bytes32 typehash, address who, uint256 value, uint256 deadline, bytes[] calldata sigs) internal {
        bytes32 structHash = _hash5(typehash, uint256(uint160(who)), value, _msNonce, deadline);
        _validateSigs(structHash, deadline, sigs);
    }

    /**
     * @notice Reconfigures the multisig via 3-of-5 multisig approval.
     */
    function reconfigureMultiSig(address[5] calldata msSigners, uint256 deadline, bytes[] calldata sigs) external {
        address s0 = msSigners[0];
        address s1 = msSigners[1];
        address s2 = msSigners[2];
        address s3 = msSigners[3];
        address s4 = msSigners[4];
        uint256 nonce = _msNonce;
        uint256 dl = deadline;
        bytes32 typehash = MS_CFG_SIGNERS_TYPEHASH;
        bytes32 structHash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), s0)
            mstore(add(ptr, 0x40), s1)
            mstore(add(ptr, 0x60), s2)
            mstore(add(ptr, 0x80), s3)
            mstore(add(ptr, 0xa0), s4)
            mstore(add(ptr, 0xc0), nonce)
            mstore(add(ptr, 0xe0), dl)
            structHash := keccak256(ptr, 0x100)
            mstore(0x40, add(ptr, 0x100))
        }
        _validateSigs(structHash, deadline, sigs);
        _configureMultiSig(msSigners);
    }

    /**
     * @notice Rescues ERC20 tokens held by this contract via 3-of-5 multisig approval.
     * @param token The ERC20 token address to rescue.
     * @param to The recipient address that will receive the rescued tokens.
     * @param amount The amount of tokens to send to `to`.
     */
    function rescueERC20(address token, address to, uint256 amount, uint256 deadline, bytes[] calldata sigs) external nonReentrant {
        require(token != address(0), "MS: zero token");
        require(to != address(0), "MS: zero to");

        bytes32 structHash = _hash6(
            MS_RESCUE_TYPEHASH,
            uint256(uint160(token)),
            uint256(uint160(to)),
            amount,
            _msNonce,
            deadline
        );
        _validateSigs(structHash, deadline, sigs);

        IERC20(token).safeTransfer(to, amount);
    }

    /**
     * @notice Pauses token transfers via 3-of-5 multisig approval.
     */
    function pause(uint256 deadline, bytes[] calldata sigs) external {
        _msAuthSimple(MS_PAUSE_TYPEHASH, deadline, sigs);
        _pause();
    }

    /**
     * @notice Unpauses token transfers via 3-of-5 multisig approval.
     */
    function unpause(uint256 deadline, bytes[] calldata sigs) external {
        _msAuthSimple(MS_UNPAUSE_TYPEHASH, deadline, sigs);
        _unpause();
    }

    /**
     * @notice Mints tokens to `_deployer` via 3-of-5 multisig approval.
     * @param amount The number of tokens to mint.
     */
    function mint(uint256 amount, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthUint(MS_MINT_TYPEHASH, amount, deadline, sigs);
        _mint(_deployer, amount);
    }

    /**
     * @notice Burns tokens from `_deployer` via 3-of-5 multisig approval.
     * @param amount The number of tokens to burn.
     */
    function burn(uint256 amount, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthUint(MS_BURN_TYPEHASH, amount, deadline, sigs);
        _burn(_deployer, amount);
    }

    /**
     * @notice Updates the deployer via 3-of-5 multisig approval.
     */
    function setDeployer(address who, uint256 deadline, bytes[] calldata sigs) external {
        require(who != address(0), "MS: zero deployer");
        require(!_isBlacklisted(who), "MS: blacklisted deployer");
        require(!_isLocked(who), "MS: locked deployer");
        _msAuthAddr(MS_SET_DEPLOYER_TYPEHASH, who, deadline, sigs);
        _deployer = who;
    }

    /**
     * @notice Locks an account for a relative duration via multisig approval.
     */
    function lockFor(address who, uint256 duration, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthAddrUint(MS_LOCK_FOR_TYPEHASH, who, duration, deadline, sigs);
        _lockFor(who, duration);
    }

    /**
     * @notice Locks an account until an absolute timestamp via multisig approval.
     */
    function lockUntil(address who, uint256 until, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthAddrUint(MS_LOCK_UNTIL_TYPEHASH, who, until, deadline, sigs);
        _lockUntil(who, until);
    }

    /**
     * @notice Unlocks an account immediately via multisig approval.
     */
    function unlock(address who, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthAddr(MS_UNLOCK_TYPEHASH, who, deadline, sigs);
        _unlock(who);
    }

    /**
     * @notice Prunes up to `max` expired locks via multisig approval.
     */
    function pruneExpiredLocks(uint256 max, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthUint(MS_PRUNE_LOCKS_TYPEHASH, max, deadline, sigs);
        _pruneExpired(max);
    }

    /**
     * @notice Adds an account to the blacklist via multisig approval.
     */
    function addBlackList(address account, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthAddr(MS_ADD_BLACK_TYPEHASH, account, deadline, sigs);
        _addBlackList(account);
    }

    /**
     * @notice Removes an account from the blacklist via multisig approval.
     */
    function removeBlackList(address account, uint256 deadline, bytes[] calldata sigs) external {
        _msAuthAddr(MS_REMOVE_BLACK_TYPEHASH, account, deadline, sigs);
        _removeBlackList(account);
    }
}
