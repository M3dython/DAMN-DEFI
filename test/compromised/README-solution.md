# Compromised Oracle Exploit Contract

This repository contains an **Exploit** contract that demonstrates a vulnerability in the `TrustfulOracle` contract used by the Exchange. The exploit leverages compromised oracle sources to manipulate NFT prices and drain the Exchange's funds.

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

- **TrustfulOracle:** A price oracle that relies on trusted sources to report prices for tokens. The final price is calculated as the median of all reported prices.
- **Exchange:** A contract that allows users to buy and sell NFTs at prices determined by the oracle.
- **Exploit Contract:** The code in `Exploit.sol` demonstrates how to manipulate oracle prices by controlling trusted sources and profiting from the price difference.

### High-Level Goal

The high-level goal is to drain all ETH from the Exchange by manipulating the NFT price through compromised oracle sources, buying low, and selling high.

---

## How the Exploit Works

1. **Understanding the Oracle Vulnerability**  
   The `TrustfulOracle` contract has a critical vulnerability:

   - It relies on trusted sources for price information
   - If a majority of trusted sources are compromised, attackers can manipulate the median price

2. **The Oracle Manipulation Process**  
   The attack follows this sequence:

   - Control at least 2 out of 3 oracle sources (majority)
   - Use the compromised sources to set the NFT price to zero
   - Buy an NFT for essentially free
   - Use the compromised sources to set the NFT price back to its original high value (999 ETH)
   - Sell the NFT back to the Exchange for the high price, draining its funds

3. **The Exploit's Strategy**  
   The exploit takes advantage of this by:

   - Creating a proxy contract that can receive and trade NFTs
   - Calling the compromised sources to manipulate prices down to zero
   - Buying an NFT at the manipulated price
   - Calling the compromised sources to manipulate prices back up
   - Selling the NFT back at the high price
   - Transferring all drained ETH to a recovery address

4. **Execution Flow**
   1. The `buy` function purchases an NFT when the price is manipulated to zero
   2. The `sell` function sells the NFT back when the price is manipulated to a high value
   3. The `recover` function transfers all drained funds to the recovery address

The vulnerability stems from the centralized trust model where a small number of sources control pricing data, making the system susceptible to price manipulation if those sources are compromised.

---

## Key Contract Components

### `constructor(TrustfulOracle _oracle, Exchange _exchange, DamnValuableNFT _nft, address _recovery) payable`

- **Parameters**:

  - `_oracle`: The TrustfulOracle contract address
  - `_exchange`: The Exchange contract address
  - `_nft`: The DamnValuableNFT contract address
  - `_recovery`: Address where drained funds should be sent

- **Behavior**: Initializes state variables and stores references to relevant contracts

### `buy() external payable`

- **Behavior**:
  - Calls the exchange's buyOne function with minimal value
  - Purchases an NFT when the price is manipulated to zero
  - Stores the NFT ID for later use

### `sell() external`

- **Behavior**:
  - Approves the exchange to transfer the NFT
  - Calls the exchange's sellOne function to sell the NFT at the manipulated high price

### `recover(uint256 amount) external`

- **Behavior**:
  - Transfers the specified amount of ETH to the recovery address
  - Completes the attack by securing the stolen funds

### `onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external pure returns (bytes4)`

- **Behavior**:
  - Required implementation for contracts receiving ERC721 tokens
  - Returns the function selector to confirm ability to receive NFTs

---

## Setup and Usage

1. **Clone the Repo & Install Dependencies**

   ```bash
   git clone <this-repo-url>
   cd compromised-exploit
   forge install
   ```

2. **Compile the Contract**

   ```bash
   forge build
   ```

3. **Run the Test**

   ```bash
   forge test -vvv --match-path test/compromised/Compromised.t.sol
   ```

4. **Understanding the Attack Flow**

   - The test deploys:
     - A TrustfulOracle with three trusted sources
     - An Exchange with 999 ETH initial balance
     - The exploit contract is deployed and manipulates prices

5. **Key Steps in the Attack**
   - Manipulate oracle price down to 0 using compromised sources
   - Buy an NFT for almost free
   - Manipulate oracle price back up to 999 ETH
   - Sell the NFT back to the Exchange at the high price
   - Transfer all drained ETH to the recovery address

---

## Security Considerations

- **Oracle Security**: The primary issue is the centralized trust model with few data sources.
- **Recommended Fixes**:

  - Increase the number of trusted sources to make manipulation more difficult
  - Implement anomaly detection for sudden price changes
  - Use time-weighted average prices instead of spot prices
  - Implement price deviation limits between updates

  ```solidity
  function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
      uint256 currentMedian = _computeMedianPrice(symbol);
      // Limit price changes to a maximum percentage (e.g., 10%)
      if (currentMedian > 0 && (newPrice > currentMedian * 110 / 100 || newPrice < currentMedian * 90 / 100)) {
          revert PriceDeviationTooLarge();
      }
      _setPrice(msg.sender, symbol, newPrice);
  }
  ```

- **Additional Security Measures**:
  - Use decentralized oracles like Chainlink
  - Implement a minimum delay between price updates
  - Require multiple signatures for extreme price changes
  - Consider using a weighted median based on source reputation
  - Implement circuit breakers for suspicious market conditions

---
