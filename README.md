# switch-contract

## Versions
- **Solidity**: `^0.8.30`  
- **OpenZeppelin**: `5.4.0`

## Switch Token is an ERC20-compatible token
- **Standard ERC20 transfers and balance management**
- **EIP-2612 permit (gasless approvals) support**
- **3-of-5 EIP-712 multisig–based administrative control**
  - Instead of using a single `owner` address (which creates a single point of failure), admin privileges are controlled by a **3-of-5 multisig** to improve security and operational robustness.
- **Blacklist policy** to restrict malicious or non-compliant accounts
- **Time-based lock mechanism** to limit spending from specific accounts for a given period
- **Global pause capability** to halt all token transfers in emergencies
- **Rescue mechanism** to recover ERC20 tokens accidentally sent to the contract

## Architecture
- **Switch (`src/Switch.sol`)**  
  - ERC20 token implementation that mints the initial supply to the deployer.  
  - Delegates all admin logic (pause, lock, blacklist, mint, burn) to `Mshelper`.  
  - Transfers are only allowed when the contract is not paused, the sender is not locked, and the sender is not blacklisted.

- **Mshelper (`src/utils/Mshelper.sol`)**  
  - Glue layer that combines `ERC20Permit`, `Pausable`, `Blacklist`, `Lockable`, `Multisig`, and `ReentrancyGuard`.  
  - Exposes multisig-protected admin functions such as `pause`, `unpause`, `mint`, `burn`, `setDeployer`, `lockFor`, `lockUntil`, `unlock`, `pruneExpiredLocks`, `addBlackList`, `removeBlackList`, and `rescueERC20`.

- **Multisig (`src/utils/Multisig.sol`)**  
  - Generic 3-of-5 EIP-712 multisig helper.  
  - Validates signatures from a fixed set of 5 signers and maintains a nonce to prevent replay.

- **Lockable (`src/utils/Lockable.sol`)**  
  - Manages time-based spending locks on accounts.  
  - Supports relative (`lockFor`) and absolute (`lockUntil`) locks, unlocking, listing locked accounts, and pruning expired locks.

- **Blacklist (`src/utils/Blacklist.sol`)**  
  - Minimal blacklist module that tracks whether an address is blocked.  
  - Used by `Switch` to prevent blacklisted accounts from transferring tokens.

## Admin Flow (Multisig)
- **Signer set**: 5 distinct multisig signers, with a fixed **3-of-5** threshold.  
- **Typed data**: Each admin action (pause, mint, burn, lock, blacklist, etc.) has its own EIP-712 typehash.  
- **Execution pattern**:
  1. Off-chain, at least 3 signers sign the EIP-712 typed data for the desired action.  
  2. The collected signatures are passed to the corresponding `Mshelper` function (e.g. `pause`, `mint`, `lockFor`).  
  3. `_validateSigs` checks signatures, threshold, deadline, and nonce, then the action is executed.

## Development
- **Install dependencies**
  - `npm install`

- **Compile & test**
  - Compile and run tasks using Hardhat (installed as a dependency), for example:
    - `npx hardhat compile`
    - `npx hardhat test` (tests need to be added)

- **Network configuration**
  - Network and deployment settings are managed via `hardhat.config.js`.  
  - Add your preferred networks and deploy scripts according to your environment.

