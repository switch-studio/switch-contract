// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Mshelper} from "src/utils/Mshelper.sol";

contract Switch is Mshelper {
    string constant private NAME = "Switch Token";
    string constant private SYMBOL = "SWC";
    uint256 constant private INITIAL_SUPPLY = 5_000_000_000 * 1e18;

    constructor(address[5] memory msSigners)
        ERC20(NAME, SYMBOL)
        ERC20Permit(NAME)
        Mshelper(msSigners)
    {
        _deployer = msg.sender;
        _mint(_deployer, INITIAL_SUPPLY);
    }

    function _update(address from, address to, uint256 value)
        internal
        override
        whenNotPaused
        whenUnlocked(from)
        whenNotBlacklist(from)
    {
        super._update(from, to, value);
    }
}
