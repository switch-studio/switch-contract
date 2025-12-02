// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title Blacklist
 * @notice Minimal blacklist management (add/remove/query) and a modifier for
 *         enforcing blacklist rules on token transfers.
 * @dev
 * - This contract by itself does not block any token movement.
 * - A token that inherits this contract (e.g. `Switch`) must apply the
 *   `whenNotBlacklist` modifier to its transfer/mint/burn logic in order
 *   for the blacklist policy to actually be enforced.
 * - Blacklist mutations are done only via the internal `_addBlackList` and
 *   `_removeBlackList` helpers (typically wrapped by multisig functions in the inheriting token).
 */
abstract contract Blacklist {
    mapping(address => bool) private _blacklisted;

    event AddedToBlacklist(address indexed account);
    event RemovedFromBlacklist(address indexed account);

    /**
     * @notice Ensures the given address is not blacklisted.
     * @param who The address to validate against the blacklist.
     */
    modifier whenNotBlacklist(address who) {
        _whenNotBlacklist(who);
        _;
    }

    /**
     * @notice Ensures the given address is not blacklisted.
     * @param who The address to validate against the blacklist.
     */
    function _whenNotBlacklist(address who) internal view {
        require(!_blacklisted[who], "whenNotBlacklist: This user is blacklisted");
    }

    /**
     * @notice Returns whether an account is currently blacklisted.
     * @param account The address to query.
     * @return True if the account is blacklisted; otherwise false.
     */
    function isBlacklisted(address account) external view returns (bool) {
        return _isBlacklisted(account);
    }

    /**
     * @notice Internal helper to check blacklist status.
     * @param account The address to query.
     * @return True if the account is blacklisted; otherwise false.
     */
    function _isBlacklisted(address account) internal view returns (bool) {
        return _blacklisted[account];
    }

    /**
     * @notice Adds an account to the blacklist.
     * @param account The address to add to the blacklist.
     * @dev Reverts for the zero address. Intended to be called only from
     *      privileged admin functions in the inheriting token (e.g. multisig).
     */
    function _addBlackList(address account) internal {
        require(account != address(0), "addBlackList: cannot add zero address");
        _blacklisted[account] = true;
        emit AddedToBlacklist(account);
    }

    /**
     * @notice Removes an account from the blacklist.
     * @param account The address to remove from the blacklist.
     * @dev Intended to be called only from privileged admin functions in
     *      the inheriting token (e.g. multisig).
     */
    function _removeBlackList(address account) internal {
        delete _blacklisted[account];
        emit RemovedFromBlacklist(account);
    }
}


