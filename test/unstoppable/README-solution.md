# Unstoppable Challenge

This repository contains a **proof-of-concept** demonstrating how to break the flash loan functionality in the `UnstoppableVault` by desynchronizing its total supply of shares from its total asset balance. Simply transferring extra tokens into the vault triggers a check that reverts any flash loan attempt.

> **Disclaimer**  
> This code is for educational and testing purposes only. Do not use in production or against systems you do not own or have explicit permission to test.

---

## Table of Contents

- [Unstoppable Challenge](#unstoppable-challenge)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [High-Level Goal](#high-level-goal)
  - [How the Exploit Works](#how-the-exploit-works)
  - [Key Contract Components](#key-contract-components)
    - [`UnstoppableChallenge.sol`](#unstoppablechallengesol)
    - [`UnstoppableVault.sol`](#unstoppablevaultsol)
    - [`UnstoppableMonitor.sol`](#unstoppablemonitorsol)
  - [Setup and Usage](#setup-and-usage)
  - [Security Considerations](#security-considerations)

---

## Overview

- **UnstoppableVault:** An ERC4626-compliant vault (`UnstoppableVault.sol`) that offers flash loans. It reverts if the number of shares in existence (`totalSupply`) does not match the balance of the underlying asset (`balanceBefore`) when a flash loan is attempted.
- **Challenge Scenario:** The challenge code (`UnstoppableChallenge.sol`) expects you to break the flash loan mechanism so that `flashLoan` becomes non-functional.

### High-Level Goal

To cause the vault’s `flashLoan()` function to fail by making `convertToShares(totalSupply)` differ from the vault's actual token balance, thereby triggering the `InvalidBalance()` error in the vault.

---

## How the Exploit Works

1. **Vault’s Invariant Check**  
   Inside the `flashLoan()` function of `UnstoppableVault`, there is a check to ensure:

   ```solidity
   if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
   ```

   This check enforces that the total shares match the vault’s asset balance in a one-to-one ratio (after any deposits/withdrawals) before flash loans are issued.

2. **Forcing a Mismatch**  
   By sending a direct token transfer to the vault (bypassing its deposit mechanism), you increase the vault’s token balance (`balanceBefore`) without increasing its recorded share balance (`totalSupply`). This discrepancy breaks the invariant:

   ```solidity
   token.transfer(address(vault), 123);
   ```

   Since `convertToShares(totalSupply)` remains tied to the original deposit/withdraw logic, it no longer matches the updated ERC20 balance in the vault.

3. **Effect on Flash Loan**  
   When the vault later checks `convertToShares(totalSupply) != balanceBefore`, it detects the imbalance and reverts the transaction. As a result, **no** flash loan can be taken, effectively making the vault “unstoppable.”

---

## Key Contract Components

### `UnstoppableChallenge.sol`

- **`setUp()`**  
  Deploys the token, the vault, and a monitoring contract (`UnstoppableMonitor`). Seeds the vault with tokens and the player with an initial token balance.
- **`test_unstoppable()`**  
  Demonstrates the core solution: transferring tokens directly to the vault to break the flash loan function.

### `UnstoppableVault.sol`

- **`flashLoan()`**  
  Implements the flash loan logic. It checks invariants before issuing a flash loan:

  ```solidity
  if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
  ```

  Any mismatch causes a revert, preventing the flash loan.

- **`execute(...)`**  
  An admin function allowing the owner to perform arbitrary calls when the vault is paused.

### `UnstoppableMonitor.sol`

- **`checkFlashLoan(uint256 amount)`**  
  Called by the owner to perform a flash loan check. If it fails, the vault is paused and ownership is transferred.

---

## Setup and Usage

1. **Clone the Repo & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   cd unstoppable-challenge
   forge install
   ```

   _(Or use your preferred tooling such as Hardhat or Truffle.)_

2. **Compile the Contracts**

   ```bash
   forge build
   ```

   _(Adapt for your chosen tool as needed.)_

3. **Deploy the Contracts**

   - Deploy `DamnValuableToken` and `UnstoppableVault`.
   - Deploy `UnstoppableMonitor`, passing in the vault address.
   - Transfer ownership of the vault to the `UnstoppableMonitor`.

4. **Run the Test/Exploit**

   - Using Foundry, run:
     ```bash
     forge test --match-contract UnstoppableChallenge
     ```
   - Observe that the flash loan function is broken after `token.transfer(address(vault), 123);`.

5. **Verification**
   - The test checks that the vault is paused, ownership is transferred back to the deployer, and that flash loans can no longer be taken.

---

## Security Considerations

- **Invariant Checks**: The vault relies on matching share supply to the token balance. Direct token transfers can break this relationship if not carefully guarded.
- **Proper Deposit/Withdrawal Flow**: In a real-world scenario, contracts should enforce that all token movements occur via deposit/withdraw functions, preventing external token transfers from causing unintended imbalances.
- **Pausing & Administrative Controls**: Once a vault is paused due to an invariant break, an admin could fix the imbalance or other vulnerabilities. Properly designed admin functions can mitigate irreparable damage.

---
