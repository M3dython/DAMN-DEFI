# Side Entrance Exploit

This repository contains an exploit contract designed to drain a vulnerable lending pool known as the **SideEntranceLenderPool**. The pool allows anyone to deposit ETH and withdraw it at any time, and it offers free flash loans using the deposited ETH. Despite having 1000 ETH deposited in it, the pool's design flaw allows an attacker starting with just 1 ETH to drain the entire balance and deposit it into a designated recovery account.

> **Disclaimer**  
> This code is for educational and testing purposes only. Do not use it in production environments or against systems without explicit authorization.

---

## Table of Contents

- [Side Entrance Exploit](#side-entrance-exploit)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [How the Exploit Works](#how-the-exploit-works)
  - [Key Contract Components](#key-contract-components)
    - [Exploit Contract](#exploit-contract)
  - [Setup and Usage](#setup-and-usage)
  - [Security Considerations](#security-considerations)
  - [License](#license)

---

## Overview

The **SideEntranceLenderPool** contract lets users deposit ETH and withdraw it later, while also providing flash loans with no fee. The vulnerability arises from the fact that the pool counts ETH deposited during a flash loan as a valid repayment. An attacker can exploit this by borrowing the entire pool balance via a flash loan, then depositing that ETH back into the pool as repayment—thus registering a deposit that can later be withdrawn.

The goal of the exploit is to:

- Borrow the pool’s ETH using the flash loan facility.
- Repay the loan by depositing the ETH back into the pool.
- Withdraw the deposited ETH.
- Transfer the withdrawn funds to a designated recovery address.

---

## How the Exploit Works

1. **Initiate Flash Loan:**  
   The exploit contract calls the pool’s `flashLoan()` function requesting the full balance (1000 ETH). The pool sends the ETH to the contract, then calls the `execute()` function on the contract.

2. **Deposit during Flash Loan Execution:**  
   Within the `execute()` function, the contract immediately deposits the borrowed ETH back into the pool by calling `deposit()`. This deposit counts as the flash loan repayment.

3. **Completing the Flash Loan:**  
   Since the ETH is redeposited, the pool’s balance remains intact, allowing the flash loan to complete without reverting.

4. **Withdrawing the Funds:**  
   After the flash loan finishes, the contract calls `withdraw()`. The pool sends the ETH that was credited as a deposit back to the contract.

5. **Transferring to Recovery:**  
   Finally, the contract transfers the withdrawn ETH to the designated recovery account, thereby rescuing all ETH from the pool.

---

## Key Contract Components

### Exploit Contract

- **State Variables:**

  - `pool`: Reference to the vulnerable **SideEntranceLenderPool**.
  - `recovery`: Address where the drained ETH will be sent.
  - `exploitAmount`: The amount of ETH to be exploited (in this case, 1000 ETH).

- **Functions:**

  - `attack() external returns (bool)`:  
    Initiates the flash loan, triggers the deposit during the flash loan callback, withdraws the credited ETH, and transfers the funds to the recovery address.

  - `execute() external payable`:  
    Called by the pool during the flash loan process. It deposits the received ETH back into the pool, effectively repaying the flash loan.

  - `receive() external payable`:  
    Fallback function to accept ETH transfers, ensuring that the contract can receive funds under any circumstances.

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

   ````
   - For Foundry:
   ```bash
   forge build
   ````

3. **Deploy the Contracts**

   - Deploy the **SideEntranceLenderPool** contract first and deposit 1000 ETH into it.
   - Deploy the **Exploit** contract by passing the pool’s address, the designated recovery address, and the amount (1000 ETH) to the constructor.

4. **Execute the Attack**

   - From the attacker's account (starting with 1 ETH), call the `attack()` function on the **Exploit** contract.
   - The exploit will perform the flash loan, deposit, withdrawal, and final transfer to the recovery address.

5. **Verification**
   - Confirm that the pool's balance is now 0 ETH.
   - Verify that the recovery account now holds 1000 ETH.

---

## Security Considerations

- **Design Flaw:**  
  The vulnerability in the **SideEntranceLenderPool** lies in its failure to separate flash loan repayment from the deposit mechanism. It inadvertently allows the reentrancy of the deposit function during a flash loan.

- **Best Practices:**  
  Contracts offering flash loans should strictly enforce repayment conditions and ensure that funds deposited during a flash loan cannot be abused to register a valid deposit.

- **Mitigation:**  
  Developers should implement proper accounting mechanisms to ensure that funds deposited during a flash loan cannot be double counted for repayment and later withdrawal.

---

## License

This project is licensed under the [MIT License](./LICENSE).

---

By following this guide, you now understand how the exploit works and the underlying vulnerability in the **SideEntranceLenderPool**. Use this knowledge responsibly and ensure that you test and audit smart contracts rigorously before deploying them to production environments.
