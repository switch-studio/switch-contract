// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title Lockable
 * @notice Account-level time locks with enumeration utilities.
 * @dev
 * - This module only tracks and enforces lock state; it does NOT define who
 *   is allowed to lock or unlock accounts.
 * - A token that inherits this contract (e.g. `Switch`) is expected to expose
 *   admin functions (typically multisig-controlled) that call the internal
 *   helpers `_lockFor`, `_lockUntil`, `_unlock`, and `_pruneExpired`.
 * - The `whenUnlocked` modifier is intended to be applied to transfer/mint/burn
 *   paths so that locked accounts cannot spend until their lock expires or is
 *   explicitly removed.
 */
abstract contract Lockable {
    /// @dev Timestamp until which the user is locked (0 means unlocked).
    mapping(address => uint256) private _lockupUntil;

    /// @dev Iterable tracking for locked addresses (may include expired entries until pruned).
    address[] private _lockedAccounts;

    /// @dev 1-based index in `_lockedAccounts` (0 means not present).
    mapping(address => uint256) private _lockedIndex;

    event Lock(address indexed who, uint256 until);
    event Unlock(address indexed who);

    /**
     * @notice Ensures the given address is not currently locked.
     * @param who The address whose lock status is being checked.
     * @dev Apply to functions that spend from `who` (e.g., `_update` with `from = who`).
     */
    modifier whenUnlocked(address who) {
        _whenUnlocked(who);
        _;
    }

    /**
     * @notice Ensures the given address is not currently locked.
     * @param who The address whose lock status is being checked.
     * @dev Apply to functions that spend from `who` (e.g., `_update` with `from = who`).
     */
    function _whenUnlocked(address who) internal view {
        require(!_isLocked(who), "whenUnlocked: This user is locked");
    }

    /**
     * @notice Locks a user's ability to spend until an absolute timestamp.
     * @param who The address to lock.
     * @param until Unix timestamp when the lock expires (must be in the future).
     * @dev
     * - Reverts on zero address or past timestamps.
     * - Emits {Lock}.
     * - Intended to be called only from privileged admin functions in the
     *   inheriting token (e.g. multisig).
     */
    function _lockUntil(address who, uint256 until) internal {
        require(who != address(0), "lockUntil: cannot lock zero address");
        require(until > block.timestamp, "lockUntil: until must be in the future");
        _lockupUntil[who] = until;
        _addLocked(who);
        emit Lock(who, until);
    }

    /**
     * @notice Locks a user's ability to spend for a relative duration.
     * @param who The address to lock.
     * @param duration The number of seconds to lock from now (must be > 0).
     * @dev
     * - Reverts on zero address or zero duration.
     * - Emits {Lock}.
     * - Intended to be called only from privileged admin functions in the
     *   inheriting token (e.g. multisig).
     */
    function _lockFor(address who, uint256 duration) internal {
        require(who != address(0), "lockFor: cannot lock zero address");
        require(duration > 0, "lockFor: duration must be > 0");
        uint256 until = block.timestamp + duration;
        _lockupUntil[who] = until;
        _addLocked(who);
        emit Lock(who, until);
    }

    /**
     * @notice Removes the lock for a user immediately.
     * @param who The address to unlock.
     * @dev
     * - Emits {Unlock}.
     * - No-op if already unlocked.
     * - Intended to be called only from privileged admin functions in the
     *   inheriting token (e.g. multisig).
     */
    function _unlock(address who) internal {
        delete _lockupUntil[who];
        _removeLocked(who);
        emit Unlock(who);
    }

    /**
     * @notice Returns whether the user is currently locked.
     * @param who The address to query.
     * @return True if now < lock expiry; false otherwise.
     */
    function isLocked(address who) external view returns (bool) {
        return _isLocked(who);
    }

    /**
     * @notice Returns the lock expiry timestamp for a user.
     * @param who The address to query.
     * @return Timestamp when the lock expires (0 if never locked or unlocked).
     */
    function lockupUntil(address who) external view returns (uint256) {
        return _lockupUntil[who];
    }

    /**
     * @notice Returns whether the user is currently locked.
     * @param who The address to query.
     * @return True if now < lock expiry; false otherwise.
     */
    function _isLocked(address who) internal view returns (bool) {
        uint256 until = _lockupUntil[who];
        return until != 0 && block.timestamp < until;
    }

    /**
     * @notice Returns the length of the internal locked list
     *         (may include expired entries until pruned).
     * @return The number of entries in the list.
     */
    function lockedCount() external view returns (uint256) {
        return _lockedAccounts.length;
    }

    /**
     * @notice Returns the raw item at an index in the locked list.
     * @param index Zero-based index into the internal array.
     * @return who The account address.
     * @return until The stored lock expiry timestamp.
     */
    function lockedAt(uint256 index) external view returns (address who, uint256 until) {
        require(index < _lockedAccounts.length, "Lockable: index out of bounds");
        who = _lockedAccounts[index];
        until = _lockupUntil[who];
    }

    /**
     * @notice Returns whether an address is present in the locked list
     *         (may be expired).
     * @param who The address to check.
     * @return True if present in the list; false otherwise.
     */
    function isInLockedList(address who) external view returns (bool) {
        return _lockedIndex[who] != 0;
    }

    /**
     * @notice Paginates currently active locks, filtering out expired/unset entries.
     * @param offset Array offset to start scanning from.
     * @param limit Maximum number of active entries to return.
     * @return accounts The addresses found (length = limit; use count).
     * @return untils The corresponding expiry timestamps (length = limit; use count).
     * @return count The number of valid entries filled in the arrays.
     * @dev
     * - Returns up to `limit` active locks starting from `offset`.
     * - The returned arrays are sized to `limit`, but only the first `count`
     *   entries are valid.
     */
    function getLocked(uint256 offset, uint256 limit)
        external
        view
        returns (address[] memory accounts, uint256[] memory untils, uint256 count)
    {
        accounts = new address[](limit);
        untils = new uint256[](limit);
        count = 0;
        uint256 len = _lockedAccounts.length;
        uint256 i = offset;
        while (i < len && count < limit) {
            address who = _lockedAccounts[i];
            uint256 until = _lockupUntil[who];
            if (until != 0 && block.timestamp < until) {
                accounts[count] = who;
                untils[count] = until;
                unchecked { count++; }
            }
            unchecked { i++; }
        }
    }

    /**
     * @notice Prunes up to `max` expired/unlocked entries from the locked list.
     * @param max The maximum number of entries to prune.
     * @return pruned The number of entries removed.
     */
    function _pruneExpired(uint256 max) internal returns (uint256 pruned) {
        pruned = 0;
        uint256 i = _lockedAccounts.length;
        while (i > 0 && pruned < max) {
            unchecked { i--; }
            address who = _lockedAccounts[i];
            if (!_isLocked(who)) {
                _removeLocked(who);
                unchecked { pruned++; }
            }
        }
    }

    /**
     * @notice Adds an address to the internal locked list if not yet present.
     * @param who The address to append.
     * @dev Internal helper to append an address to the list if not yet present.
     */
    function _addLocked(address who) internal {
        if (_lockedIndex[who] == 0) {
            _lockedAccounts.push(who);
            // store index + 1
            _lockedIndex[who] = _lockedAccounts.length;
        }
    }

    /**
     * @notice Removes an address from the internal locked list, if present.
     * @param who The address to remove.
     * @dev Internal helper to remove an address from the list, if present.
     */
    function _removeLocked(address who) internal {
        uint256 idx = _lockedIndex[who];
        if (idx == 0) return; // not present
        uint256 lastIdx = _lockedAccounts.length;
        if (lastIdx == 0) return;
        // convert to 0-based
        uint256 i = idx - 1;
        uint256 j = lastIdx - 1;
        if (i != j) {
            address last = _lockedAccounts[j];
            _lockedAccounts[i] = last;
            _lockedIndex[last] = idx; // keep 1-based
        }
        _lockedAccounts.pop();
        delete _lockedIndex[who];
    }
}