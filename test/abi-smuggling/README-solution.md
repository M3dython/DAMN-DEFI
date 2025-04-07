# Exploit Contract

This repository contains an **Exploit** contract that demonstrates how to craft a specific calldata payload to bypass certain protections in a hypothetical vault contract called `SelfAuthorizedVault`. The exploit leverages the vault's `execute()` function to invoke another function (`sweepFunds()`) in an unauthorized manner.

> **Disclaimer**  
> This code is for educational and testing purposes only. Do not use in production or against systems you do not own or have explicit permission to test.

---

## Table of Contents

- [Exploit Contract](#exploit-contract)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [High-Level Goal](#high-level-goal)
  - [How the Exploit Works](#how-the-exploit-works)
  - [Key Contract Components](#key-contract-components)
    - [`constructor(address _vault, address _token, address _recovery)`](#constructoraddress-_vault-address-_token-address-_recovery)
    - [`executeExploit() external returns (bytes memory)`](#executeexploit-external-returns-bytes-memory)
  - [Setup and Usage](#setup-and-usage)
  - [Security Considerations](#security-considerations)

---

## Overview

- **Vault:** A contract (`SelfAuthorizedVault`) with an `execute()` function that expects data in a very specific format (including target address, data offset, action data, etc.).
- **Exploit Contract:** The code in [Exploit.sol](./Exploit.sol) shows how to craft the calldata such that the vault’s `execute()` function ends up calling `sweepFunds()` and sending tokens to an attacker-controlled address.

### High-Level Goal

The high-level goal is to trick the vault into calling its own privileged `sweepFunds(address to, IERC20 token)` function by providing a carefully structured payload to `execute()`, effectively draining tokens to an unauthorized recipient.

---

## How the Exploit Works

1. **Vault's `execute` Function**  
   The `SelfAuthorizedVault` has a function `execute(bytes calldata data)` or some variant that interprets the provided `data` in a very particular way:

   1. It checks the first part of the calldata for the target contract address (padded to 32 bytes).
   2. It then reads the next part to figure out where the "action data" begins.
   3. Finally, it executes that action data on the target contract.

2. **Crafting the Calldata**  
   To exploit this mechanism, the attacker constructs the calldata in a way that:

   - **Selector for `execute()`:** The first 4 bytes are the function selector for `execute()`.
   - **Target Address (Vault):** The next 32 bytes encode the vault’s address. In normal usage, this might be some other contract’s address, but here it’s pointed back to the vault itself.
   - **Data Offset:** The following 32 bytes specify where the payload for the **next** call (the action data) begins.
   - **Empty Data / Padding:** Additional 32 bytes of zeroed data to align the payload properly in memory.
   - **Fake Function Selector:** A 32-byte chunk that fakes a call to `withdraw()` or another function. In reality, the vault’s logic will skip over this due to the structure of `execute()`.
   - **Calldata Length & Action Data:** Finally, the exploit includes the actual data for `sweepFunds(address to, IERC20 token)`, which will cause the vault to send tokens to the attacker’s `recovery` address.

3. **Triggering the Exploit**  
   Once the malicious calldata is constructed, the attacker simply calls `vault.execute(calldataPayload)`, causing the vault to:
   - Parse the payload,
   - Call itself (`vault`) as the target,
   - Invoke `sweepFunds(recovery, token)`,
   - Transfer the specified `token` balance from the vault to the attacker's `recovery` address.

In essence, the exploit hinges on the vault allowing arbitrary calls via `execute()`, assuming the caller is “self-authorized” or not performing enough validation of the action data.

---

## Key Contract Components

### `constructor(address _vault, address _token, address _recovery)`

- **Parameters**:

  - `_vault`: The address of the vault to exploit (an instance of `SelfAuthorizedVault`).
  - `_token`: The address of the ERC20 token to be drained.
  - `_recovery`: The address where the drained funds will be sent.

- **Behavior**: Initializes state variables so the contract knows which vault to target, which token to drain, and where to send the tokens.

### `executeExploit() external returns (bytes memory)`

- **Access Control**: Restricted to the contract deployer (`player`).
- **Goal**: Constructs the correct calldata to force the vault to call its own `sweepFunds()` function, sending tokens to `recovery`.
- **Return Value**: Returns the raw `calldataPayload` that would be passed to `vault.execute()`.

The function outlines each step involved in building the exploit payload, including:

- Getting the `execute()` function selector.
- Encoding the vault’s address.
- Specifying the memory offsets.
- Padding the data.
- Embedding the `sweepFunds()` function call with the desired parameters.

---

## Setup and Usage

1. **Clone the Repo & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   npm install
   ```

   Or if using Foundry:

   ```bash
   forge install
   ```

2. **Compile the Contract**

   - **Hardhat/Truffle**: `npx hardhat compile`
   - **Foundry**: `forge build`

3. **Deploy the Exploit Contract**

   - Deploy `SelfAuthorizedVault` first (or obtain an address if already deployed).
   - Deploy an ERC20 token contract (or reuse an existing one).
   - Deploy `Exploit` by passing `_vault`, `_token`, and `_recovery` to the constructor.

   For example, in a Hardhat script:

   ```js
   const Exploit = await ethers.getContractFactory("Exploit");
   const exploit = await Exploit.deploy(
     vaultAddress,
     tokenAddress,
     attackerRecoveryAddress
   );
   await exploit.deployed();
   ```

4. **Execute the Exploit**

   - Call `exploit.executeExploit()`.
   - This returns the `calldataPayload` which you can directly send in a transaction to `vault.execute(calldataPayload)`—or in some scenarios, you might do a direct low-level call in the same script.

   ```js
   const payload = await exploit.executeExploit();
   await vaultContract.execute(payload);
   ```

5. **Verification**
   - Check the token balance of `attackerRecoveryAddress` to see if the exploit was successful.

---

## Security Considerations

- **Permissions & Validation**: The root issue here is that the `SelfAuthorizedVault` does not sufficiently validate the origin or structure of calls made via `execute()`. It relies on a “self-authorization” assumption without thorough checks.
- **Calldata Crafting**: Solidity contracts reading raw calldata can be tricked if they do not carefully parse or validate each field. The exploit demonstrates how encoding details can be manipulated to bypass these checks.
- **Mitigation**: The vault should enforce strict access control, ensuring only authorized addresses (or roles) can call sensitive functions like `sweepFunds()`. Another approach is to verify that any calls to `execute()` come from a known, trusted origin and that the target is correct, not allowing the vault to call itself freely.

---
