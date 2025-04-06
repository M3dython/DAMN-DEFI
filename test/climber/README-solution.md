# Climber Exploit Contract

This repository contains an **Exploit** contract that demonstrates a vulnerability in the `ClimberTimelock` contract, which is designed to implement a delayed execution mechanism for sensitive operations. The exploit leverages a logical flaw in the execution flow to bypass timelock restrictions and gain control of the vault's assets.

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

- **ClimberTimelock:** A contract that implements a time-delayed execution mechanism for sensitive operations. It requires operations to be scheduled and wait for a delay period before execution.
- **ClimberVault:** A contract that holds valuable tokens and is controlled by the timelock contract.
- **Exploit Contract:** The code in `Exploit.sol` demonstrates how to bypass the timelock protection by exploiting the execution order in the `execute` function.

### High-Level Goal

The high-level goal is to drain all tokens from the `ClimberVault` by exploiting the timelock mechanism, gaining control of the vault, and transferring all assets to a recovery wallet.

---

## How the Exploit Works

1. **Understanding the Timelock Flaw**  
   The `ClimberTimelock` contract has a critical vulnerability in its `execute` function:

   - Operations are executed **before** their state is checked
   - This inverted order allows for exploitation where operations can modify the contract state before verification

2. **The Execution Order Vulnerability**  
   Normally, the expected flow would be:

   - Schedule an operation
   - Wait for the delay period
   - Execute the operation after validation

   However, due to the flawed implementation, we can:

   - Call `execute` with operations that haven't been scheduled yet
   - Include an operation that retroactively schedules itself
   - Execute privileged operations without waiting for the delay

3. **The Exploit's Strategy**  
   The exploit takes advantage of this by:

   - Creating a set of operations that grant proposer role to the exploit contract
   - Setting the delay to zero
   - Transferring ownership of the vault
   - Scheduling these operations retroactively within the same transaction
   - Upgrading the vault implementation to add a withdrawal function
   - Withdrawing all tokens to the recovery address

4. **Execution Flow**
   1. The `timelockExecute` function calls the timelock's execute function with crafted operations
   2. These operations modify permissions, delay, and ownership
   3. One of the operations calls back to the exploit to schedule the operations that are currently executing
   4. After execution, the vault is upgraded with a malicious implementation
   5. All tokens are withdrawn from the vault to the recovery address

The vulnerability stems from executing operations before validating their legitimacy, creating a circular dependency that can be exploited.

---

## Key Contract Components

### `constructor(address payable _timelock, address _vault)`

- **Parameters**:

  - `_timelock`: The ClimberTimelock contract address
  - `_vault`: The ClimberVault contract address

- **Behavior**: Initializes state variables and prepares the payload for the exploit, including the four critical operations:
  1. Grant proposer role to the exploit contract
  2. Update delay to zero
  3. Transfer vault ownership
  4. Schedule the operations being executed

### `timelockExecute() external`

- **Behavior**:
  - Calls the timelock's execute function with the crafted operations
  - Exploits the execution-before-validation vulnerability

### `timelockSchedule() external`

- **Behavior**:
  - Called by the timelock during exploit execution
  - Schedules the operations that are already being executed
  - Creates a circular reference that bypasses the timelock protection

### `PawnedClimberVault` (Upgrade Implementation)

- **Behavior**:
  - Custom vault implementation with an added `withdrawAll` function
  - Used to extract all tokens after the vault ownership is transferred

---

## Setup and Usage

1. **Clone the Repo & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   cd climber-exploit
   forge install
   ```

2. **Compile the Contract**

   ```bash
   forge build
   ```

3. **Run the Test**

   ```bash
   forge test -vvv --match-path test/climber/Climber.t.sol
   ```

4. **Understanding the Deployment**

   - The test deploys:
     - A ClimberTimelock contract
     - A ClimberVault with valuable tokens
     - The exploit contract is then deployed and used to attack the timelock and vault

5. **Verification**
   - After execution, all tokens should be transferred to the recovery address
   - The exploit consists of a single transaction that bypasses the timelock

---

## Security Considerations

- **Execution Order Vulnerabilities**: The primary issue is that operations are executed before their legitimacy is verified, allowing for exploitation.
- **Recommended Fixes**:

  - Always validate operations **before** executing them
  - Fix the `execute` function to check operation state first:

    ```solidity
    function execute(...) external payable {
        bytes32 id = getOperationId(targets, values, dataElements, salt);

        // Check state BEFORE execution
        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        // Only execute if validation passes
        for (uint8 i = 0; i < targets.length; ++i) {
            targets[i].functionCallWithValue(dataElements[i], values[i]);
        }

        operations[id].executed = true;
    }
    ```

- **Additional Security Measures**:
  - Implement access control for the `execute` function
  - Add a cooldown period between scheduling and execution
  - Use a multi-signature scheme for sensitive operations
  - Consider implementing a role-based permissions model with separation of duties

---
