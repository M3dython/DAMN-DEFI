# Truster Challenge

This repository contains a vulnerable flashloan pool contract, **TrusterLenderPool**, which offers free flashloans of DVT tokens. The pool holds 1 million DVT tokens, and the challenge is to rescue these funds by exploiting a flaw in the pool's flashloan mechanism. The exploit leverages an arbitrary call vulnerability in the `flashLoan()` function, allowing an attacker to approve and then transfer the tokens to a designated recovery account—all within a single transaction.

> **Disclaimer**  
> This code is for educational and testing purposes only. Do not use in production or against systems you do not own or have explicit permission to test.

---

## Table of Contents

- [Truster Challenge](#truster-challenge)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Vulnerability Details](#vulnerability-details)
  - [How the Exploit Works](#how-the-exploit-works)
  - [Key Contract Components](#key-contract-components)
    - [`TrusterLenderPool`](#trusterlenderpool)
    - [`Exploit` Contract](#exploit-contract)
  - [Setup and Usage](#setup-and-usage)
  - [Security Considerations](#security-considerations)

---

## Overview

- **Pool Description:**  
  The `TrusterLenderPool` contract offers flashloans of DVT tokens. It holds 1 million DVT tokens, and anyone can borrow tokens for free as long as the tokens are returned by the end of the transaction.

- **Challenge Objective:**  
  The goal is to drain all tokens from the pool and deposit them into a specified recovery account, while the player is restricted to executing only a single transaction.

---

## Vulnerability Details

The vulnerability lies in the `flashLoan()` function of the pool. This function performs an external call using `target.functionCall(data)` without proper validation of the target or the calldata. As a result, an attacker can:

- Use the flashloan to trigger an arbitrary call on any contract.
- Execute a call to the token contract to approve the attacker for spending the pool’s tokens.
- Transfer the approved tokens from the pool to the recovery account, effectively draining the pool.

---

## How the Exploit Works

1. **Initiating the Flashloan:**  
   The attacker calls `flashLoan()` with a loan amount of zero (or any amount), specifying:

   - **Borrower:** The attacker’s own address.
   - **Target:** The address of the DVT token contract.
   - **Data:** A crafted payload that encodes a call to `approve(address spender, uint256 amount)`.

2. **Arbitrary Call Execution:**  
   The pool’s `flashLoan()` function transfers tokens (if any) and then executes the arbitrary call. The payload instructs the token contract to approve the attacker for the full balance of tokens held in the pool.

3. **Draining the Pool:**  
   After the flashloan completes, the attacker uses the approved allowance to transfer all tokens from the pool to the designated recovery account, fulfilling the challenge requirements—all in one transaction.

---

## Key Contract Components

### `TrusterLenderPool`

- **flashLoan(uint256 amount, address borrower, address target, bytes calldata data):**  
  Offers a flashloan and then makes an external call to `target` with the provided `data`. The lack of validation on `target` and `data` is the core vulnerability.

### `Exploit` Contract

- **Constructor:**  
  Executes the exploit in its constructor:

  - Constructs the calldata to call `approve(address,uint256)` on the token contract.
  - Calls `flashLoan()` with this crafted data.
  - Uses the newly granted approval to transfer the tokens from the pool to the recovery account.

- **Usage in Test:**  
  The test case deploys the `Exploit` contract with the pool’s address, token address, and recovery account. The entire exploit is executed within the constructor, ensuring only one transaction is executed by the player.

---

## Setup and Usage

1. **Clone the Repository & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   npm install
   ```

   Or if using Foundry:

   ```bash
   forge install
   ```

2. **Compile the Contracts**

   - **Hardhat/Truffle:** `npx hardhat compile`
   - **Foundry:** `forge build`

3. **Deploy the Contracts**

   - Deploy the `DamnValuableToken` contract.
   - Deploy the `TrusterLenderPool` and fund it with 1 million DVT tokens.
   - Deploy the `Exploit` contract by passing the pool address, token address, and recovery account address to its constructor.

   Example using a Hardhat script:

   ```js
   const Exploit = await ethers.getContractFactory("Exploit");
   const exploit = await Exploit.deploy(
     poolAddress,
     tokenAddress,
     recoveryAddress
   );
   await exploit.deployed();
   ```

4. **Run the Test**  
   Execute the test case which validates:

   - Only one transaction is executed by the player.
   - All tokens have been transferred from the pool to the recovery account.

   The test snippet:

   ```solidity
   function test_truster() public checkSolvedByPlayer {
       Exploit exploit = new Exploit(address(pool), address(token), address(recovery));
   }
   ```

---

## Security Considerations

- **Arbitrary Call Vulnerability:**  
  The primary issue is the unchecked external call in `flashLoan()`, which allows execution of any function on any contract. This highlights the dangers of delegating execution without strict validation of both the target and the calldata.

- **Mitigation:**  
  To prevent such vulnerabilities, contracts should:
  - Validate the `target` address to ensure it is a trusted contract.
  - Restrict or sanitize the calldata passed into external calls.
  - Enforce strict controls on flashloan operations, ensuring that no unauthorized approvals or transfers can occur.

---
