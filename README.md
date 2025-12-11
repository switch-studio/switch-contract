# switch-contract

## Versions
- **Solidity**: `^0.8.30`  
- **OpenZeppelin**: `5.4.0`

## Switch Token is an ERC20-compatible token
- **Standard ERC20 transfers and balance management**
- **EIP-2612 permit (gasless approvals) support**
- **3-of-5 EIP-712 multisig–based administrative control**
  - Instead of using a single `owner` address (which creates a single point of failure), admin privileges are controlled by a **3-of-5 multisig** to improve security and operational robustness.
- **Time-based lock mechanism** to limit spending from specific accounts for a given period
- **Rescue mechanism** to recover ERC20 tokens accidentally sent to the contract

## Deployment
- **Network**: BNB Smart Chain (BSC)  
- **Token address**: [`0x03b60e802f936b18f422862c53dfaad6bf42719f`](https://bscscan.com/token/0x03b60e802f936b18f422862c53dfaad6bf42719f#code)

## Architecture
- **Switch (`src/Switch.sol`)**  
  - ERC20 token implementation that mints the initial supply to the deployer.  
  - Delegates all admin logic (lock) to `Mshelper`.  
  - Transfers are only allowed when the sender is not locked.

- **Mshelper (`src/utils/Mshelper.sol`)**  
  - Glue layer that combines `ERC20Permit`, `Lockable`, `Multisig`, and `ReentrancyGuard`.  
  - Exposes multisig-protected admin functions such as `setDeployer`, `lockFor`, `lockUntil`, `unlock`, `pruneExpiredLocks`, and `rescueERC20`.

- **Multisig (`src/utils/Multisig.sol`)**  
  - Generic 3-of-5 EIP-712 multisig helper.  
  - Validates signatures from a fixed set of 5 signers and maintains a nonce to prevent replay.

- **Lockable (`src/utils/Lockable.sol`)**  
  - Manages time-based spending locks on accounts.  
  - Supports relative (`lockFor`) and absolute (`lockUntil`) locks, unlocking, listing locked accounts, and pruning expired locks.

## Admin Flow (Multisig)
- **Signer set**: 5 distinct multisig signers, with a fixed **3-of-5** threshold.  
- **Typed data**: Each admin action (lock, etc.) has its own EIP-712 typehash.  
- **Execution pattern**:
  1. Off-chain, at least 3 signers sign the EIP-712 typed data for the desired action.  
  2. The collected signatures are passed to the corresponding `Mshelper` function (e.g. `lockFor`).  
  3. `_validateSigs` checks signatures, threshold, deadline, and nonce, then the action is executed.
