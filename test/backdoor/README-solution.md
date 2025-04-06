# Backdoor Exploit Contract

This repository contains an **Exploit** contract that demonstrates a vulnerability in the `WalletRegistry` contract, which is designed to distribute tokens to Safe multisig wallets created by registered beneficiaries. The exploit leverages Safe's initialization process to create wallets on behalf of beneficiaries while gaining control of their funds.

> **Disclaimer**  
> This code is for educational and testing purposes only. Do not use in production or against systems you do not own or have explicit permission to test.

---

## Table of Contents

1. [Overview](#overview)
2. [How the Exploit Works](#how-the-exploit-works)
3. [Key Contract Components](#key-contract-components)
4. [Setup and Usage](#setup-and-usage)
5. [Security Considerations](#security-considerations)

---

## Overview

- **WalletRegistry:** A contract that awards tokens to newly-created Safe wallets belonging to registered beneficiaries. It implements verification checks to ensure only legitimate single-owner Safe wallets receive tokens.
- **Exploit Contract:** The code in `Exploit.sol` demonstrates how to bypass these protections by creating wallets on behalf of beneficiaries while injecting malicious initialization code.

### High-Level Goal

The high-level goal is to drain all tokens (40 ETH of DVT) from the `WalletRegistry` by creating wallets for the registered beneficiaries in a way that gives the attacker control over the distributed tokens, without requiring the beneficiaries' consent or participation.

---

## How the Exploit Works

1. **Understanding Safe Wallet Creation**  
   The Safe contract allows for flexible initialization through its `setup` function, including the ability to:

   - Specify owners and threshold
   - Define a contract to delegate-call during initialization
   - Include calldata to be executed during the delegate call

2. **The WalletRegistry's Verification**  
   The registry performs several checks to ensure wallets are legitimate:

   - Verifies the correct threshold (1) and owner count (1)
   - Confirms the owner is a registered beneficiary
   - Checks for no fallback manager
   - However, it doesn't inspect the delegate call behavior during setup

3. **The Exploit's Strategy**  
   For each beneficiary, the exploit:

   - Creates a Safe wallet with the legitimate beneficiary as the owner
   - Sets up a delegate call to the exploit contract itself
   - Uses this delegate call to approve the exploit contract to spend tokens
   - Once the registry transfers tokens to the wallet, immediately transfers them to a recovery address

4. **Execution Flow**
   1. The `attack` function loops through each beneficiary
   2. For each, it creates a Safe proxy with specifically crafted initialization data
   3. The registry validates and approves the wallet, sending tokens to it
   4. Through the pre-approved spending allowance, the exploit drains the tokens

In essence, the vulnerability lies in the registry not detecting that the wallet initialization includes malicious delegate calls that compromise the tokens' security.

---

## Key Contract Components

### `constructor(address _masterCopy, address _walletFactory, address _registry, address _token, address _recovery)`

- **Parameters**:

  - `_masterCopy`: The Safe singleton implementation address
  - `_walletFactory`: The SafeProxyFactory address
  - `_registry`: The WalletRegistry address to be exploited
  - `_token`: The DamnValuableToken address to be drained
  - `_recovery`: The address where drained funds will be sent

- **Behavior**: Initializes state variables needed for the exploit to function.

### `attack(address[] memory _beneficiaries) external`

- **Parameters**:

  - `_beneficiaries`: Array of beneficiary addresses registered in the WalletRegistry

- **Behavior**:
  - Loops through beneficiaries
  - Creates wallets on their behalf with specially crafted initialization data
  - Drains tokens from each newly created wallet to the recovery address

### `delegateApprove(address _spender) external`

- **Parameters**:

  - `_spender`: Address to approve for token spending (the exploit contract itself)

- **Behavior**:
  - Called via delegate call during wallet initialization
  - Approves the exploit contract to spend tokens from the wallet
  - Called in the context of the wallet, giving the exploit permission to transfer funds later

---

## Setup and Usage

1. **Clone the Repo & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   cd backdoor-exploit
   forge install
   ```

2. **Compile the Contract**

   ```bash
   forge build
   ```

3. **Run the Test**

   ```bash
   forge test -vvv --match-path test/backdoor/Backdoor.t.sol
   ```

4. **Understanding the Deployment**

   - The test deploys:
     - A Safe singleton implementation
     - A SafeProxyFactory
     - A DamnValuableToken with 40 ETH worth of tokens
     - A WalletRegistry with four beneficiaries
   - The exploit contract is then deployed and used to attack the registry

5. **Verification**
   - After execution, all 40 ETH of DVT tokens should be transferred to the recovery address
   - All beneficiaries should have wallets registered in the WalletRegistry
   - The player should execute only a single transaction (deploying the exploit contract)

---

## Security Considerations

- **Initialization Vulnerabilities**: The primary issue is that Safe's flexible initialization process allows malicious actors to execute arbitrary code via delegate calls during setup.
- **Proxy Pattern Risks**: Proxy contracts like Safe require careful security checks, especially during initialization when they may execute untrusted code.
- **Mitigation Strategies**:
  - The WalletRegistry should validate that no delegate calls are performed during wallet setup
  - Alternatively, it could require additional proof of wallet ownership beyond just checking the owner array
  - Consider restricting wallet registration to only allow beneficiaries themselves to register wallets
  - Implement time delays or additional verification steps for token distribution

---
