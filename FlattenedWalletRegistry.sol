// SPDX-License-Identifier: MIT
pragma solidity <0.9.0 =0.8.25 >=0.7.0 ^0.8.20 ^0.8.4;

// lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol

// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/IERC20.sol)

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// lib/safe-smart-account/contracts/common/Enum.sol

/**
 * @title Enum - Collection of enums used in Safe contracts.
 * @author Richard Meissner - @rmeissner
 */
abstract contract Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}

// lib/safe-smart-account/contracts/common/NativeCurrencyPaymentFallback.sol

/**
 * @title NativeCurrencyPaymentFallback - A contract that has a fallback to accept native currency payments.
 * @author Richard Meissner - @rmeissner
 */
abstract contract NativeCurrencyPaymentFallback {
    event SafeReceived(address indexed sender, uint256 value);

    /**
     * @notice Receive function accepts native currency transactions.
     * @dev Emits an event with sender and received value.
     */
    receive() external payable {
        emit SafeReceived(msg.sender, msg.value);
    }
}

// lib/safe-smart-account/contracts/common/SecuredTokenTransfer.sol

/**
 * @title SecuredTokenTransfer - Secure token transfer.
 * @author Richard Meissner - @rmeissner
 */
abstract contract SecuredTokenTransfer {
    /**
     * @notice Transfers a token and returns a boolean if it was a success
     * @dev It checks the return data of the transfer call and returns true if the transfer was successful.
     *      It doesn't check if the `token` address is a contract or not.
     * @param token Token that should be transferred
     * @param receiver Receiver to whom the token should be transferred
     * @param amount The amount of tokens that should be transferred
     * @return transferred Returns true if the transfer was successful
     */
    function transferToken(address token, address receiver, uint256 amount) internal returns (bool transferred) {
        // 0xa9059cbb - keccack("transfer(address,uint256)")
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, receiver, amount);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // We write the return value to scratch space.
            // See https://docs.soliditylang.org/en/v0.7.6/internals/layout_in_memory.html#layout-in-memory
            let success := call(sub(gas(), 10000), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            switch returndatasize()
            case 0 {
                transferred := success
            }
            case 0x20 {
                transferred := iszero(or(iszero(success), iszero(mload(0))))
            }
            default {
                transferred := 0
            }
        }
    }
}

// lib/safe-smart-account/contracts/common/SelfAuthorized.sol

/**
 * @title SelfAuthorized - Authorizes current contract to perform actions to itself.
 * @author Richard Meissner - @rmeissner
 */
abstract contract SelfAuthorized {
    function requireSelfCall() private view {
        require(msg.sender == address(this), "GS031");
    }

    modifier authorized() {
        // Modifiers are copied around during compilation. This is a function call as it minimized the bytecode size
        requireSelfCall();
        _;
    }
}

// lib/safe-smart-account/contracts/common/SignatureDecoder.sol

/**
 * @title SignatureDecoder - Decodes signatures encoded as bytes
 * @author Richard Meissner - @rmeissner
 */
abstract contract SignatureDecoder {
    /**
     * @notice Splits signature bytes into `uint8 v, bytes32 r, bytes32 s`.
     * @dev Make sure to perform a bounds check for @param pos, to avoid out of bounds access on @param signatures
     *      The signature format is a compact form of {bytes32 r}{bytes32 s}{uint8 v}
     *      Compact means uint8 is not padded to 32 bytes.
     * @param pos Which signature to read.
     *            A prior bounds check of this parameter should be performed, to avoid out of bounds access.
     * @param signatures Concatenated {r, s, v} signatures.
     * @return v Recovery ID or Safe signature type.
     * @return r Output value r of the signature.
     * @return s Output value s of the signature.
     */
    function signatureSplit(bytes memory signatures, uint256 pos) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            /**
             * Here we are loading the last 32 bytes, including 31 bytes
             * of 's'. There is no 'mload8' to do this.
             * 'byte' is not working due to the Solidity parser, so lets
             * use the second best option, 'and'
             */
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }
}

// lib/safe-smart-account/contracts/common/Singleton.sol

/**
 * @title Singleton - Base for singleton contracts (should always be the first super contract)
 *        This contract is tightly coupled to our proxy contract (see `proxies/SafeProxy.sol`)
 * @author Richard Meissner - @rmeissner
 */
abstract contract Singleton {
    // singleton always has to be the first declared variable to ensure the same location as in the Proxy contract.
    // It should also always be ensured the address is stored alone (uses a full word)
    address private singleton;
}

// lib/safe-smart-account/contracts/common/StorageAccessible.sol

/**
 * @title StorageAccessible - A generic base contract that allows callers to access all internal storage.
 * @notice See https://github.com/gnosis/util-contracts/blob/bb5fe5fb5df6d8400998094fb1b32a178a47c3a1/contracts/StorageAccessible.sol
 *         It removes a method from the original contract not needed for the Safe contracts.
 * @author Gnosis Developers
 */
abstract contract StorageAccessible {
    /**
     * @notice Reads `length` bytes of storage in the currents contract
     * @param offset - the offset in the current contract's storage in words to start reading from
     * @param length - the number of words (32 bytes) of data to read
     * @return the bytes that were read.
     */
    function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory) {
        bytes memory result = new bytes(length * 32);
        for (uint256 index = 0; index < length; index++) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
        }
        return result;
    }

    /**
     * @dev Performs a delegatecall on a targetContract in the context of self.
     * Internally reverts execution to avoid side effects (making it static).
     *
     * This method reverts with data equal to `abi.encode(bool(success), bytes(response))`.
     * Specifically, the `returndata` after a call to this method will be:
     * `success:bool || response.length:uint256 || response:bytes`.
     *
     * @param targetContract Address of the contract containing the code to execute.
     * @param calldataPayload Calldata that should be sent to the target contract (encoded method name and arguments).
     */
    function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let success := delegatecall(gas(), targetContract, add(calldataPayload, 0x20), mload(calldataPayload), 0, 0)

            mstore(0x00, success)
            mstore(0x20, returndatasize())
            returndatacopy(0x40, 0, returndatasize())
            revert(0, add(returndatasize(), 0x40))
        }
    }
}

// lib/safe-smart-account/contracts/external/SafeMath.sol

/**
 * @title SafeMath
 * @notice Math operations with safety checks that revert on error (overflow/underflow)
 */
library SafeMath {
    /**
     * @notice Multiplies two numbers, reverts on overflow.
     * @param a First number
     * @param b Second number
     * @return Product of a and b
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
     * @notice Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
     * @param a First number
     * @param b Second number
     * @return Difference of a and b
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
     * @notice Adds two numbers, reverts on overflow.
     * @param a First number
     * @param b Second number
     * @return Sum of a and b
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    /**
     * @notice Returns the largest of two numbers.
     * @param a First number
     * @param b Second number
     * @return Largest of a and b
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }
}

// lib/safe-smart-account/contracts/interfaces/IERC165.sol

/// @notice More details at https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/introspection/IERC165.sol
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by `interfaceId`.
     * See the corresponding EIP section
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// lib/safe-smart-account/contracts/interfaces/ISignatureValidator.sol

contract ISignatureValidatorConstants {
    // bytes4(keccak256("isValidSignature(bytes,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
}

abstract contract ISignatureValidator is ISignatureValidatorConstants {
    /**
     * @notice Legacy EIP1271 method to validate a signature.
     * @param _data Arbitrary length data signed on the behalf of address(this).
     * @param _signature Signature byte array associated with _data.
     *
     * MUST return the bytes4 magic value 0x20c13b0b when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes memory _data, bytes memory _signature) public view virtual returns (bytes4);
}

// lib/safe-smart-account/contracts/proxies/SafeProxy.sol

/**
 * @title IProxy - Helper interface to access the singleton address of the Proxy on-chain.
 * @author Richard Meissner - @rmeissner
 */
interface IProxy {
    function masterCopy() external view returns (address);
}

/**
 * @title SafeProxy - Generic proxy contract allows to execute all transactions applying the code of a master contract.
 * @author Stefan George - <stefan@gnosis.io>
 * @author Richard Meissner - <richard@gnosis.io>
 */
contract SafeProxy {
    // Singleton always needs to be first declared variable, to ensure that it is at the same location in the contracts to which calls are delegated.
    // To reduce deployment costs this variable is internal and needs to be retrieved via `getStorageAt`
    address internal singleton;

    /**
     * @notice Constructor function sets address of singleton contract.
     * @param _singleton Singleton address.
     */
    constructor(address _singleton) {
        require(_singleton != address(0), "Invalid singleton address provided");
        singleton = _singleton;
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let _singleton := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            // 0xa619486e == keccak("masterCopy()"). The value is right padded to 32-bytes with 0s
            if eq(calldataload(0), 0xa619486e00000000000000000000000000000000000000000000000000000000) {
                mstore(0, _singleton)
                return(0, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

// lib/solady/src/auth/Ownable.sol

/// @notice Simple single owner authorization mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/auth/Ownable.sol)
///
/// @dev Note:
/// This implementation does NOT auto-initialize the owner to `msg.sender`.
/// You MUST call the `_initializeOwner` in the constructor / initializer.
///
/// While the ownable portion follows
/// [EIP-173](https://eips.ethereum.org/EIPS/eip-173) for compatibility,
/// the nomenclature for the 2-step ownership handover may be unique to this codebase.
abstract contract Ownable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The caller is not authorized to call the function.
    error Unauthorized();

    /// @dev The `newOwner` cannot be the zero address.
    error NewOwnerIsZeroAddress();

    /// @dev The `pendingOwner` does not have a valid handover request.
    error NoHandoverRequest();

    /// @dev Cannot double-initialize.
    error AlreadyInitialized();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ownership is transferred from `oldOwner` to `newOwner`.
    /// This event is intentionally kept the same as OpenZeppelin's Ownable to be
    /// compatible with indexers and [EIP-173](https://eips.ethereum.org/EIPS/eip-173),
    /// despite it not being as lightweight as a single argument event.
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    /// @dev An ownership handover to `pendingOwner` has been requested.
    event OwnershipHandoverRequested(address indexed pendingOwner);

    /// @dev The ownership handover to `pendingOwner` has been canceled.
    event OwnershipHandoverCanceled(address indexed pendingOwner);

    /// @dev `keccak256(bytes("OwnershipTransferred(address,address)"))`.
    uint256 private constant _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE =
        0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0;

    /// @dev `keccak256(bytes("OwnershipHandoverRequested(address)"))`.
    uint256 private constant _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE =
        0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d;

    /// @dev `keccak256(bytes("OwnershipHandoverCanceled(address)"))`.
    uint256 private constant _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE =
        0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The owner slot is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_OWNER_SLOT_NOT")))))`.
    /// It is intentionally chosen to be a high value
    /// to avoid collision with lower slots.
    /// The choice of manual storage layout is to enable compatibility
    /// with both regular and upgradeable contracts.
    bytes32 internal constant _OWNER_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;

    /// The ownership handover slot of `newOwner` is given by:
    /// ```
    ///     mstore(0x00, or(shl(96, user), _HANDOVER_SLOT_SEED))
    ///     let handoverSlot := keccak256(0x00, 0x20)
    /// ```
    /// It stores the expiry timestamp of the two-step ownership handover.
    uint256 private constant _HANDOVER_SLOT_SEED = 0x389a75e1;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Override to return true to make `_initializeOwner` prevent double-initialization.
    function _guardInitializeOwner() internal pure virtual returns (bool guard) {}

    /// @dev Initializes the owner directly without authorization guard.
    /// This function must be called upon initialization,
    /// regardless of whether the contract is upgradeable or not.
    /// This is to enable generalization to both regular and upgradeable contracts,
    /// and to save gas in case the initial owner is not the caller.
    /// For performance reasons, this function will not check if there
    /// is an existing owner.
    function _initializeOwner(address newOwner) internal virtual {
        if (_guardInitializeOwner()) {
            /// @solidity memory-safe-assembly
            assembly {
                let ownerSlot := _OWNER_SLOT
                if sload(ownerSlot) {
                    mstore(0x00, 0x0dc149f0) // `AlreadyInitialized()`.
                    revert(0x1c, 0x04)
                }
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Store the new value.
                sstore(ownerSlot, or(newOwner, shl(255, iszero(newOwner))))
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, 0, newOwner)
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Store the new value.
                sstore(_OWNER_SLOT, newOwner)
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, 0, newOwner)
            }
        }
    }

    /// @dev Sets the owner directly without authorization guard.
    function _setOwner(address newOwner) internal virtual {
        if (_guardInitializeOwner()) {
            /// @solidity memory-safe-assembly
            assembly {
                let ownerSlot := _OWNER_SLOT
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, sload(ownerSlot), newOwner)
                // Store the new value.
                sstore(ownerSlot, or(newOwner, shl(255, iszero(newOwner))))
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                let ownerSlot := _OWNER_SLOT
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, sload(ownerSlot), newOwner)
                // Store the new value.
                sstore(ownerSlot, newOwner)
            }
        }
    }

    /// @dev Throws if the sender is not the owner.
    function _checkOwner() internal view virtual {
        /// @solidity memory-safe-assembly
        assembly {
            // If the caller is not the stored owner, revert.
            if iszero(eq(caller(), sload(_OWNER_SLOT))) {
                mstore(0x00, 0x82b42900) // `Unauthorized()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /// @dev Returns how long a two-step ownership handover is valid for in seconds.
    /// Override to return a different value if needed.
    /// Made internal to conserve bytecode. Wrap it in a public function if needed.
    function _ownershipHandoverValidFor() internal view virtual returns (uint64) {
        return 48 * 3600;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  PUBLIC UPDATE FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Allows the owner to transfer the ownership to `newOwner`.
    function transferOwnership(address newOwner) public payable virtual onlyOwner {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(shl(96, newOwner)) {
                mstore(0x00, 0x7448fbae) // `NewOwnerIsZeroAddress()`.
                revert(0x1c, 0x04)
            }
        }
        _setOwner(newOwner);
    }

    /// @dev Allows the owner to renounce their ownership.
    function renounceOwnership() public payable virtual onlyOwner {
        _setOwner(address(0));
    }

    /// @dev Request a two-step ownership handover to the caller.
    /// The request will automatically expire in 48 hours (172800 seconds) by default.
    function requestOwnershipHandover() public payable virtual {
        unchecked {
            uint256 expires = block.timestamp + _ownershipHandoverValidFor();
            /// @solidity memory-safe-assembly
            assembly {
                // Compute and set the handover slot to `expires`.
                mstore(0x0c, _HANDOVER_SLOT_SEED)
                mstore(0x00, caller())
                sstore(keccak256(0x0c, 0x20), expires)
                // Emit the {OwnershipHandoverRequested} event.
                log2(0, 0, _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE, caller())
            }
        }
    }

    /// @dev Cancels the two-step ownership handover to the caller, if any.
    function cancelOwnershipHandover() public payable virtual {
        /// @solidity memory-safe-assembly
        assembly {
            // Compute and set the handover slot to 0.
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, caller())
            sstore(keccak256(0x0c, 0x20), 0)
            // Emit the {OwnershipHandoverCanceled} event.
            log2(0, 0, _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE, caller())
        }
    }

    /// @dev Allows the owner to complete the two-step ownership handover to `pendingOwner`.
    /// Reverts if there is no existing ownership handover requested by `pendingOwner`.
    function completeOwnershipHandover(address pendingOwner) public payable virtual onlyOwner {
        /// @solidity memory-safe-assembly
        assembly {
            // Compute and set the handover slot to 0.
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, pendingOwner)
            let handoverSlot := keccak256(0x0c, 0x20)
            // If the handover does not exist, or has expired.
            if gt(timestamp(), sload(handoverSlot)) {
                mstore(0x00, 0x6f5e8818) // `NoHandoverRequest()`.
                revert(0x1c, 0x04)
            }
            // Set the handover slot to 0.
            sstore(handoverSlot, 0)
        }
        _setOwner(pendingOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   PUBLIC READ FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the owner of the contract.
    function owner() public view virtual returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := sload(_OWNER_SLOT)
        }
    }

    /// @dev Returns the expiry timestamp for the two-step ownership handover to `pendingOwner`.
    function ownershipHandoverExpiresAt(address pendingOwner)
        public
        view
        virtual
        returns (uint256 result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Compute the handover slot.
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, pendingOwner)
            // Load the handover slot.
            result := sload(keccak256(0x0c, 0x20))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         MODIFIERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Marks a function as only callable by the owner.
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }
}

// lib/solady/src/utils/SafeTransferLib.sol

/// @notice Safe ETH and ERC20 transfer library that gracefully handles missing return values.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SafeTransferLib.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol)
/// @author Permit2 operations from (https://github.com/Uniswap/permit2/blob/main/src/libraries/Permit2Lib.sol)
///
/// @dev Note:
/// - For ETH transfers, please use `forceSafeTransferETH` for DoS protection.
/// - For ERC20s, this implementation won't check that a token has code,
///   responsibility is delegated to the caller.
library SafeTransferLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ETH transfer has failed.
    error ETHTransferFailed();

    /// @dev The ERC20 `transferFrom` has failed.
    error TransferFromFailed();

    /// @dev The ERC20 `transfer` has failed.
    error TransferFailed();

    /// @dev The ERC20 `approve` has failed.
    error ApproveFailed();

    /// @dev The Permit2 operation has failed.
    error Permit2Failed();

    /// @dev The Permit2 amount must be less than `2**160 - 1`.
    error Permit2AmountOverflow();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Suggested gas stipend for contract receiving ETH that disallows any storage writes.
    uint256 internal constant GAS_STIPEND_NO_STORAGE_WRITES = 2300;

    /// @dev Suggested gas stipend for contract receiving ETH to perform a few
    /// storage reads and writes, but low enough to prevent griefing.
    uint256 internal constant GAS_STIPEND_NO_GRIEF = 100000;

    /// @dev The unique EIP-712 domain domain separator for the DAI token contract.
    bytes32 internal constant DAI_DOMAIN_SEPARATOR =
        0xdbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7;

    /// @dev The address for the WETH9 contract on Ethereum mainnet.
    address internal constant WETH9 = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    /// @dev The canonical Permit2 address.
    /// [Github](https://github.com/Uniswap/permit2)
    /// [Etherscan](https://etherscan.io/address/0x000000000022D473030F116dDEE9F6B43aC78BA3)
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ETH OPERATIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // If the ETH transfer MUST succeed with a reasonable gas budget, use the force variants.
    //
    // The regular variants:
    // - Forwards all remaining gas to the target.
    // - Reverts if the target reverts.
    // - Reverts if the current contract has insufficient balance.
    //
    // The force variants:
    // - Forwards with an optional gas stipend
    //   (defaults to `GAS_STIPEND_NO_GRIEF`, which is sufficient for most cases).
    // - If the target reverts, or if the gas stipend is exhausted,
    //   creates a temporary contract to force send the ETH via `SELFDESTRUCT`.
    //   Future compatible with `SENDALL`: https://eips.ethereum.org/EIPS/eip-4758.
    // - Reverts if the current contract has insufficient balance.
    //
    // The try variants:
    // - Forwards with a mandatory gas stipend.
    // - Instead of reverting, returns whether the transfer succeeded.

    /// @dev Sends `amount` (in wei) ETH to `to`.
    function safeTransferETH(address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(call(gas(), to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /// @dev Sends all the ETH in the current contract to `to`.
    function safeTransferAllETH(address to) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // Transfer all the ETH and check if it succeeded or not.
            if iszero(call(gas(), to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /// @dev Force sends `amount` (in wei) ETH to `to`, with a `gasStipend`.
    function forceSafeTransferETH(address to, uint256 amount, uint256 gasStipend) internal {
        /// @solidity memory-safe-assembly
        assembly {
            if lt(selfbalance(), amount) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
            if iszero(call(gasStipend, to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) // Store the address in scratch space.
                mstore8(0x0b, 0x73) // Opcode `PUSH20`.
                mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
                if iszero(create(amount, 0x0b, 0x16)) { revert(codesize(), codesize()) } // For gas estimation.
            }
        }
    }

    /// @dev Force sends all the ETH in the current contract to `to`, with a `gasStipend`.
    function forceSafeTransferAllETH(address to, uint256 gasStipend) internal {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(call(gasStipend, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) // Store the address in scratch space.
                mstore8(0x0b, 0x73) // Opcode `PUSH20`.
                mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
                if iszero(create(selfbalance(), 0x0b, 0x16)) { revert(codesize(), codesize()) } // For gas estimation.
            }
        }
    }

    /// @dev Force sends `amount` (in wei) ETH to `to`, with `GAS_STIPEND_NO_GRIEF`.
    function forceSafeTransferETH(address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            if lt(selfbalance(), amount) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
            if iszero(call(GAS_STIPEND_NO_GRIEF, to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) // Store the address in scratch space.
                mstore8(0x0b, 0x73) // Opcode `PUSH20`.
                mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
                if iszero(create(amount, 0x0b, 0x16)) { revert(codesize(), codesize()) } // For gas estimation.
            }
        }
    }

    /// @dev Force sends all the ETH in the current contract to `to`, with `GAS_STIPEND_NO_GRIEF`.
    function forceSafeTransferAllETH(address to) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // forgefmt: disable-next-item
            if iszero(call(GAS_STIPEND_NO_GRIEF, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) // Store the address in scratch space.
                mstore8(0x0b, 0x73) // Opcode `PUSH20`.
                mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
                if iszero(create(selfbalance(), 0x0b, 0x16)) { revert(codesize(), codesize()) } // For gas estimation.
            }
        }
    }

    /// @dev Sends `amount` (in wei) ETH to `to`, with a `gasStipend`.
    function trySafeTransferETH(address to, uint256 amount, uint256 gasStipend)
        internal
        returns (bool success)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gasStipend, to, amount, codesize(), 0x00, codesize(), 0x00)
        }
    }

    /// @dev Sends all the ETH in the current contract to `to`, with a `gasStipend`.
    function trySafeTransferAllETH(address to, uint256 gasStipend)
        internal
        returns (bool success)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gasStipend, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ERC20 OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    /// Reverts upon failure.
    ///
    /// The `from` account must have at least `amount` approved for
    /// the current contract to manage.
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x60, amount) // Store the `amount` argument.
            mstore(0x40, to) // Store the `to` argument.
            mstore(0x2c, shl(96, from)) // Store the `from` argument.
            mstore(0x0c, 0x23b872dd000000000000000000000000) // `transferFrom(address,address,uint256)`.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) // `TransferFromFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) // Restore the zero slot to zero.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    ///
    /// The `from` account must have at least `amount` approved for the current contract to manage.
    function trySafeTransferFrom(address token, address from, address to, uint256 amount)
        internal
        returns (bool success)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x60, amount) // Store the `amount` argument.
            mstore(0x40, to) // Store the `to` argument.
            mstore(0x2c, shl(96, from)) // Store the `from` argument.
            mstore(0x0c, 0x23b872dd000000000000000000000000) // `transferFrom(address,address,uint256)`.
            success :=
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            mstore(0x60, 0) // Restore the zero slot to zero.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Sends all of ERC20 `token` from `from` to `to`.
    /// Reverts upon failure.
    ///
    /// The `from` account must have their entire balance approved for the current contract to manage.
    function safeTransferAllFrom(address token, address from, address to)
        internal
        returns (uint256 amount)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x40, to) // Store the `to` argument.
            mstore(0x2c, shl(96, from)) // Store the `from` argument.
            mstore(0x0c, 0x70a08231000000000000000000000000) // `balanceOf(address)`.
            // Read the balance, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                    staticcall(gas(), token, 0x1c, 0x24, 0x60, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) // `TransferFromFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x00, 0x23b872dd) // `transferFrom(address,address,uint256)`.
            amount := mload(0x60) // The `amount` is already at 0x60. We'll need to return it.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) // `TransferFromFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) // Restore the zero slot to zero.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Sends `amount` of ERC20 `token` from the current contract to `to`.
    /// Reverts upon failure.
    function safeTransfer(address token, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, to) // Store the `to` argument.
            mstore(0x34, amount) // Store the `amount` argument.
            mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /// @dev Sends all of ERC20 `token` from the current contract to `to`.
    /// Reverts upon failure.
    function safeTransferAll(address token, address to) internal returns (uint256 amount) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0x70a08231) // Store the function selector of `balanceOf(address)`.
            mstore(0x20, address()) // Store the address of the current contract.
            // Read the balance, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                    staticcall(gas(), token, 0x1c, 0x24, 0x34, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x14, to) // Store the `to` argument.
            amount := mload(0x34) // The `amount` is already at 0x34. We'll need to return it.
            mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /// @dev Sets `amount` of ERC20 `token` for `to` to manage on behalf of the current contract.
    /// Reverts upon failure.
    function safeApprove(address token, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, to) // Store the `to` argument.
            mstore(0x34, amount) // Store the `amount` argument.
            mstore(0x00, 0x095ea7b3000000000000000000000000) // `approve(address,uint256)`.
            // Perform the approval, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x3e3f8f73) // `ApproveFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /// @dev Sets `amount` of ERC20 `token` for `to` to manage on behalf of the current contract.
    /// If the initial attempt to approve fails, attempts to reset the approved amount to zero,
    /// then retries the approval again (some tokens, e.g. USDT, requires this).
    /// Reverts upon failure.
    function safeApproveWithRetry(address token, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, to) // Store the `to` argument.
            mstore(0x34, amount) // Store the `amount` argument.
            mstore(0x00, 0x095ea7b3000000000000000000000000) // `approve(address,uint256)`.
            // Perform the approval, retrying upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x34, 0) // Store 0 for the `amount`.
                mstore(0x00, 0x095ea7b3000000000000000000000000) // `approve(address,uint256)`.
                pop(call(gas(), token, 0, 0x10, 0x44, codesize(), 0x00)) // Reset the approval.
                mstore(0x34, amount) // Store back the original `amount`.
                // Retry the approval, reverting upon failure.
                if iszero(
                    and(
                        or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                        call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                    )
                ) {
                    mstore(0x00, 0x3e3f8f73) // `ApproveFailed()`.
                    revert(0x1c, 0x04)
                }
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /// @dev Returns the amount of ERC20 `token` owned by `account`.
    /// Returns zero if the `token` does not exist.
    function balanceOf(address token, address account) internal view returns (uint256 amount) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, account) // Store the `account` argument.
            mstore(0x00, 0x70a08231000000000000000000000000) // `balanceOf(address)`.
            amount :=
                mul( // The arguments of `mul` are evaluated from right to left.
                    mload(0x20),
                    and( // The arguments of `and` are evaluated from right to left.
                        gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                        staticcall(gas(), token, 0x10, 0x24, 0x20, 0x20)
                    )
                )
        }
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    /// If the initial attempt fails, try to use Permit2 to transfer the token.
    /// Reverts upon failure.
    ///
    /// The `from` account must have at least `amount` approved for the current contract to manage.
    function safeTransferFrom2(address token, address from, address to, uint256 amount) internal {
        if (!trySafeTransferFrom(token, from, to, amount)) {
            permit2TransferFrom(token, from, to, amount);
        }
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to` via Permit2.
    /// Reverts upon failure.
    function permit2TransferFrom(address token, address from, address to, uint256 amount)
        internal
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(add(m, 0x74), shr(96, shl(96, token)))
            mstore(add(m, 0x54), amount)
            mstore(add(m, 0x34), to)
            mstore(add(m, 0x20), shl(96, from))
            // `transferFrom(address,address,uint160,address)`.
            mstore(m, 0x36c78516000000000000000000000000)
            let p := PERMIT2
            let exists := eq(chainid(), 1)
            if iszero(exists) { exists := iszero(iszero(extcodesize(p))) }
            if iszero(and(call(gas(), p, 0, add(m, 0x10), 0x84, codesize(), 0x00), exists)) {
                mstore(0x00, 0x7939f4248757f0fd) // `TransferFromFailed()` or `Permit2AmountOverflow()`.
                revert(add(0x18, shl(2, iszero(iszero(shr(160, amount))))), 0x04)
            }
        }
    }

    /// @dev Permit a user to spend a given amount of
    /// another user's tokens via native EIP-2612 permit if possible, falling
    /// back to Permit2 if native permit fails or is not implemented on the token.
    function permit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        bool success;
        /// @solidity memory-safe-assembly
        assembly {
            for {} shl(96, xor(token, WETH9)) {} {
                mstore(0x00, 0x3644e515) // `DOMAIN_SEPARATOR()`.
                if iszero(
                    and( // The arguments of `and` are evaluated from right to left.
                        lt(iszero(mload(0x00)), eq(returndatasize(), 0x20)), // Returns 1 non-zero word.
                        // Gas stipend to limit gas burn for tokens that don't refund gas when
                        // an non-existing function is called. 5K should be enough for a SLOAD.
                        staticcall(5000, token, 0x1c, 0x04, 0x00, 0x20)
                    )
                ) { break }
                // After here, we can be sure that token is a contract.
                let m := mload(0x40)
                mstore(add(m, 0x34), spender)
                mstore(add(m, 0x20), shl(96, owner))
                mstore(add(m, 0x74), deadline)
                if eq(mload(0x00), DAI_DOMAIN_SEPARATOR) {
                    mstore(0x14, owner)
                    mstore(0x00, 0x7ecebe00000000000000000000000000) // `nonces(address)`.
                    mstore(add(m, 0x94), staticcall(gas(), token, 0x10, 0x24, add(m, 0x54), 0x20))
                    mstore(m, 0x8fcbaf0c000000000000000000000000) // `IDAIPermit.permit`.
                    // `nonces` is already at `add(m, 0x54)`.
                    // `1` is already stored at `add(m, 0x94)`.
                    mstore(add(m, 0xb4), and(0xff, v))
                    mstore(add(m, 0xd4), r)
                    mstore(add(m, 0xf4), s)
                    success := call(gas(), token, 0, add(m, 0x10), 0x104, codesize(), 0x00)
                    break
                }
                mstore(m, 0xd505accf000000000000000000000000) // `IERC20Permit.permit`.
                mstore(add(m, 0x54), amount)
                mstore(add(m, 0x94), and(0xff, v))
                mstore(add(m, 0xb4), r)
                mstore(add(m, 0xd4), s)
                success := call(gas(), token, 0, add(m, 0x10), 0xe4, codesize(), 0x00)
                break
            }
        }
        if (!success) simplePermit2(token, owner, spender, amount, deadline, v, r, s);
    }

    /// @dev Simple permit on the Permit2 contract.
    function simplePermit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, 0x927da105) // `allowance(address,address,address)`.
            {
                let addressMask := shr(96, not(0))
                mstore(add(m, 0x20), and(addressMask, owner))
                mstore(add(m, 0x40), and(addressMask, token))
                mstore(add(m, 0x60), and(addressMask, spender))
                mstore(add(m, 0xc0), and(addressMask, spender))
            }
            let p := mul(PERMIT2, iszero(shr(160, amount)))
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    gt(returndatasize(), 0x5f), // Returns 3 words: `amount`, `expiration`, `nonce`.
                    staticcall(gas(), p, add(m, 0x1c), 0x64, add(m, 0x60), 0x60)
                )
            ) {
                mstore(0x00, 0x6b836e6b8757f0fd) // `Permit2Failed()` or `Permit2AmountOverflow()`.
                revert(add(0x18, shl(2, iszero(p))), 0x04)
            }
            mstore(m, 0x2b67b570) // `Permit2.permit` (PermitSingle variant).
            // `owner` is already `add(m, 0x20)`.
            // `token` is already at `add(m, 0x40)`.
            mstore(add(m, 0x60), amount)
            mstore(add(m, 0x80), 0xffffffffffff) // `expiration = type(uint48).max`.
            // `nonce` is already at `add(m, 0xa0)`.
            // `spender` is already at `add(m, 0xc0)`.
            mstore(add(m, 0xe0), deadline)
            mstore(add(m, 0x100), 0x100) // `signature` offset.
            mstore(add(m, 0x120), 0x41) // `signature` length.
            mstore(add(m, 0x140), r)
            mstore(add(m, 0x160), s)
            mstore(add(m, 0x180), shl(248, v))
            if iszero(call(gas(), p, 0, add(m, 0x1c), 0x184, codesize(), 0x00)) {
                mstore(0x00, 0x6b836e6b) // `Permit2Failed()`.
                revert(0x1c, 0x04)
            }
        }
    }
}

// lib/safe-smart-account/contracts/base/Executor.sol

/**
 * @title Executor - A contract that can execute transactions
 * @author Richard Meissner - @rmeissner
 */
abstract contract Executor {
    /**
     * @notice Executes either a delegatecall or a call with provided parameters.
     * @dev This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      It is the responsibility of the caller to perform such checks.
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @return success boolean flag indicating if the call succeeded.
     */
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
        if (operation == Enum.Operation.DelegateCall) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
            }
        } else {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
            }
        }
    }
}

// lib/safe-smart-account/contracts/base/FallbackManager.sol

/**
 * @title Fallback Manager - A contract managing fallback calls made to this contract
 * @author Richard Meissner - @rmeissner
 */
abstract contract FallbackManager is SelfAuthorized {
    event ChangedFallbackHandler(address indexed handler);

    // keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_HANDLER_STORAGE_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /**
     *  @notice Internal function to set the fallback handler.
     *  @param handler contract to handle fallback calls.
     */
    function internalSetFallbackHandler(address handler) internal {
        /*
            If a fallback handler is set to self, then the following attack vector is opened:
            Imagine we have a function like this:
            function withdraw() internal authorized {
                withdrawalAddress.call.value(address(this).balance)("");
            }

            If the fallback method is triggered, the fallback handler appends the msg.sender address to the calldata and calls the fallback handler.
            A potential attacker could call a Safe with the 3 bytes signature of a withdraw function. Since 3 bytes do not create a valid signature,
            the call would end in a fallback handler. Since it appends the msg.sender address to the calldata, the attacker could craft an address 
            where the first 3 bytes of the previous calldata + the first byte of the address make up a valid function signature. The subsequent call would result in unsanctioned access to Safe's internal protected methods.
            For some reason, solidity matches the first 4 bytes of the calldata to a function signature, regardless if more data follow these 4 bytes.
        */
        require(handler != address(this), "GS400");

        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, handler)
        }
    }

    /**
     * @notice Set Fallback Handler to `handler` for the Safe.
     * @dev Only fallback calls without value and with data will be forwarded.
     *      This can only be done via a Safe transaction.
     *      Cannot be set to the Safe itself.
     * @param handler contract to handle fallback calls.
     */
    function setFallbackHandler(address handler) public authorized {
        internalSetFallbackHandler(handler);
        emit ChangedFallbackHandler(handler);
    }

    // @notice Forwards all calls to the fallback handler if set. Returns 0 if no handler is set.
    // @dev Appends the non-padded caller address to the calldata to be optionally used in the handler
    //      The handler can make us of `HandlerContext.sol` to extract the address.
    //      This is done because in the next call frame the `msg.sender` will be FallbackManager's address
    //      and having the original caller address may enable additional verification scenarios.
    // solhint-disable-next-line payable-fallback,no-complex-fallback
    fallback() external {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let handler := sload(slot)
            if iszero(handler) {
                return(0, 0)
            }
            calldatacopy(0, 0, calldatasize())
            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            mstore(calldatasize(), shl(96, caller()))
            // Add 20 bytes for the address appended add the end
            let success := call(gas(), handler, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

// lib/safe-smart-account/contracts/base/OwnerManager.sol

/**
 * @title OwnerManager - Manages Safe owners and a threshold to authorize transactions.
 * @dev Uses a linked list to store the owners because the code generate by the solidity compiler
 *      is more efficient than using a dynamic array.
 * @author Stefan George - @Georgi87
 * @author Richard Meissner - @rmeissner
 */
abstract contract OwnerManager is SelfAuthorized {
    event AddedOwner(address indexed owner);
    event RemovedOwner(address indexed owner);
    event ChangedThreshold(uint256 threshold);

    address internal constant SENTINEL_OWNERS = address(0x1);

    mapping(address => address) internal owners;
    uint256 internal ownerCount;
    uint256 internal threshold;

    /**
     * @notice Sets the initial storage of the contract.
     * @param _owners List of Safe owners.
     * @param _threshold Number of required confirmations for a Safe transaction.
     */
    function setupOwners(address[] memory _owners, uint256 _threshold) internal {
        // Threshold can only be 0 at initialization.
        // Check ensures that setup function can only be called once.
        require(threshold == 0, "GS200");
        // Validate that threshold is smaller than number of added owners.
        require(_threshold <= _owners.length, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        // Initializing Safe owners.
        address currentOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < _owners.length; i++) {
            // Owner address cannot be null.
            address owner = _owners[i];
            require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
            // No duplicate owners allowed.
            require(owners[owner] == address(0), "GS204");
            owners[currentOwner] = owner;
            currentOwner = owner;
        }
        owners[currentOwner] = SENTINEL_OWNERS;
        ownerCount = _owners.length;
        threshold = _threshold;
    }

    /**
     * @notice Adds the owner `owner` to the Safe and updates the threshold to `_threshold`.
     * @dev This can only be done via a Safe transaction.
     * @param owner New owner address.
     * @param _threshold New threshold.
     */
    function addOwnerWithThreshold(address owner, uint256 _threshold) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[owner] == address(0), "GS204");
        owners[owner] = owners[SENTINEL_OWNERS];
        owners[SENTINEL_OWNERS] = owner;
        ownerCount++;
        emit AddedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /**
     * @notice Removes the owner `owner` from the Safe and updates the threshold to `_threshold`.
     * @dev This can only be done via a Safe transaction.
     * @param prevOwner Owner that pointed to the owner to be removed in the linked list
     * @param owner Owner address to be removed.
     * @param _threshold New threshold.
     */
    function removeOwner(address prevOwner, address owner, uint256 _threshold) public authorized {
        // Only allow to remove an owner, if threshold can still be reached.
        require(ownerCount - 1 >= _threshold, "GS201");
        // Validate owner address and check that it corresponds to owner index.
        require(owner != address(0) && owner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == owner, "GS205");
        owners[prevOwner] = owners[owner];
        owners[owner] = address(0);
        ownerCount--;
        emit RemovedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /**
     * @notice Replaces the owner `oldOwner` in the Safe with `newOwner`.
     * @dev This can only be done via a Safe transaction.
     * @param prevOwner Owner that pointed to the owner to be replaced in the linked list
     * @param oldOwner Owner address to be replaced.
     * @param newOwner New owner address.
     */
    function swapOwner(address prevOwner, address oldOwner, address newOwner) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(newOwner != address(0) && newOwner != SENTINEL_OWNERS && newOwner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[newOwner] == address(0), "GS204");
        // Validate oldOwner address and check that it corresponds to owner index.
        require(oldOwner != address(0) && oldOwner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == oldOwner, "GS205");
        owners[newOwner] = owners[oldOwner];
        owners[prevOwner] = newOwner;
        owners[oldOwner] = address(0);
        emit RemovedOwner(oldOwner);
        emit AddedOwner(newOwner);
    }

    /**
     * @notice Changes the threshold of the Safe to `_threshold`.
     * @dev This can only be done via a Safe transaction.
     * @param _threshold New threshold.
     */
    function changeThreshold(uint256 _threshold) public authorized {
        // Validate that threshold is smaller than number of owners.
        require(_threshold <= ownerCount, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        threshold = _threshold;
        emit ChangedThreshold(threshold);
    }

    /**
     * @notice Returns the number of required confirmations for a Safe transaction aka the threshold.
     * @return Threshold number.
     */
    function getThreshold() public view returns (uint256) {
        return threshold;
    }

    /**
     * @notice Returns if `owner` is an owner of the Safe.
     * @return Boolean if owner is an owner of the Safe.
     */
    function isOwner(address owner) public view returns (bool) {
        return owner != SENTINEL_OWNERS && owners[owner] != address(0);
    }

    /**
     * @notice Returns a list of Safe owners.
     * @return Array of Safe owners.
     */
    function getOwners() public view returns (address[] memory) {
        address[] memory array = new address[](ownerCount);

        // populate return array
        uint256 index = 0;
        address currentOwner = owners[SENTINEL_OWNERS];
        while (currentOwner != SENTINEL_OWNERS) {
            array[index] = currentOwner;
            currentOwner = owners[currentOwner];
            index++;
        }
        return array;
    }
}

// lib/safe-smart-account/contracts/proxies/IProxyCreationCallback.sol

/**
 * @title IProxyCreationCallback
 * @dev An interface for a contract that implements a callback function to be executed after the creation of a proxy instance.
 */
interface IProxyCreationCallback {
    /**
     * @dev Function to be called after the creation of a SafeProxy instance.
     * @param proxy The newly created SafeProxy instance.
     * @param _singleton The address of the singleton contract used to create the proxy.
     * @param initializer The initializer function call data.
     * @param saltNonce The nonce used to generate the salt for the proxy deployment.
     */
    function proxyCreated(SafeProxy proxy, address _singleton, bytes calldata initializer, uint256 saltNonce) external;
}

// lib/safe-smart-account/contracts/base/GuardManager.sol

interface Guard is IERC165 {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

abstract contract BaseGuard is Guard {
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return
            interfaceId == type(Guard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }
}

/**
 * @title Guard Manager - A contract managing transaction guards which perform pre and post-checks on Safe transactions.
 * @author Richard Meissner - @rmeissner
 */
abstract contract GuardManager is SelfAuthorized {
    event ChangedGuard(address indexed guard);

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /**
     * @dev Set a guard that checks transactions before execution
     *      This can only be done via a Safe transaction.
     *      ⚠️ IMPORTANT: Since a guard has full power to block Safe transaction execution,
     *        a broken guard can cause a denial of service for the Safe. Make sure to carefully
     *        audit the guard code and design recovery mechanisms.
     * @notice Set Transaction Guard `guard` for the Safe. Make sure you trust the guard.
     * @param guard The address of the guard to be used or the 0 address to disable the guard
     */
    function setGuard(address guard) external authorized {
        if (guard != address(0)) {
            require(Guard(guard).supportsInterface(type(Guard).interfaceId), "GS300");
        }
        bytes32 slot = GUARD_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, guard)
        }
        emit ChangedGuard(guard);
    }

    /**
     * @dev Internal method to retrieve the current guard
     *      We do not have a public method because we're short on bytecode size limit,
     *      to retrieve the guard address, one can use `getStorageAt` from `StorageAccessible` contract
     *      with the slot `GUARD_STORAGE_SLOT`
     * @return guard The address of the guard
     */
    function getGuard() internal view returns (address guard) {
        bytes32 slot = GUARD_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            guard := sload(slot)
        }
    }
}

// lib/safe-smart-account/contracts/base/ModuleManager.sol

/**
 * @title Module Manager - A contract managing Safe modules
 * @notice Modules are extensions with unlimited access to a Safe that can be added to a Safe by its owners.
           ⚠️ WARNING: Modules are a security risk since they can execute arbitrary transactions, 
           so only trusted and audited modules should be added to a Safe. A malicious module can
           completely takeover a Safe.
 * @author Stefan George - @Georgi87
 * @author Richard Meissner - @rmeissner
 */
abstract contract ModuleManager is SelfAuthorized, Executor {
    event EnabledModule(address indexed module);
    event DisabledModule(address indexed module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);

    address internal constant SENTINEL_MODULES = address(0x1);

    mapping(address => address) internal modules;

    /**
     * @notice Setup function sets the initial storage of the contract.
     *         Optionally executes a delegate call to another contract to setup the modules.
     * @param to Optional destination address of call to execute.
     * @param data Optional data of call to execute.
     */
    function setupModules(address to, bytes memory data) internal {
        require(modules[SENTINEL_MODULES] == address(0), "GS100");
        modules[SENTINEL_MODULES] = SENTINEL_MODULES;
        if (to != address(0)) {
            require(isContract(to), "GS002");
            // Setup has to complete successfully or transaction fails.
            require(execute(to, 0, data, Enum.Operation.DelegateCall, type(uint256).max), "GS000");
        }
    }

    /**
     * @notice Enables the module `module` for the Safe.
     * @dev This can only be done via a Safe transaction.
     * @param module Module to be whitelisted.
     */
    function enableModule(address module) public authorized {
        // Module address cannot be null or sentinel.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        // Module cannot be added twice.
        require(modules[module] == address(0), "GS102");
        modules[module] = modules[SENTINEL_MODULES];
        modules[SENTINEL_MODULES] = module;
        emit EnabledModule(module);
    }

    /**
     * @notice Disables the module `module` for the Safe.
     * @dev This can only be done via a Safe transaction.
     * @param prevModule Previous module in the modules linked list.
     * @param module Module to be removed.
     */
    function disableModule(address prevModule, address module) public authorized {
        // Validate module address and check that it corresponds to module index.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        require(modules[prevModule] == module, "GS103");
        modules[prevModule] = modules[module];
        modules[module] = address(0);
        emit DisabledModule(module);
    }

    /**
     * @notice Execute `operation` (0: Call, 1: DelegateCall) to `to` with `value` (Native Token)
     * @dev Function is virtual to allow overriding for L2 singleton to emit an event for indexing.
     * @param to Destination address of module transaction.
     * @param value Ether value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type of module transaction.
     * @return success Boolean flag indicating if the call succeeded.
     */
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public virtual returns (bool success) {
        // Only whitelisted modules are allowed.
        require(msg.sender != SENTINEL_MODULES && modules[msg.sender] != address(0), "GS104");
        // Execute transaction without further confirmations.
        success = execute(to, value, data, operation, type(uint256).max);
        if (success) emit ExecutionFromModuleSuccess(msg.sender);
        else emit ExecutionFromModuleFailure(msg.sender);
    }

    /**
     * @notice Execute `operation` (0: Call, 1: DelegateCall) to `to` with `value` (Native Token) and return data
     * @param to Destination address of module transaction.
     * @param value Ether value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type of module transaction.
     * @return success Boolean flag indicating if the call succeeded.
     * @return returnData Data returned by the call.
     */
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public returns (bool success, bytes memory returnData) {
        success = execTransactionFromModule(to, value, data, operation);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            returnData := ptr
        }
    }

    /**
     * @notice Returns if an module is enabled
     * @return True if the module is enabled
     */
    function isModuleEnabled(address module) public view returns (bool) {
        return SENTINEL_MODULES != module && modules[module] != address(0);
    }

    /**
     * @notice Returns an array of modules.
     *         If all entries fit into a single page, the next pointer will be 0x1.
     *         If another page is present, next will be the last element of the returned array.
     * @param start Start of the page. Has to be a module or start pointer (0x1 address)
     * @param pageSize Maximum number of modules that should be returned. Has to be > 0
     * @return array Array of modules.
     * @return next Start of the next page.
     */
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory array, address next) {
        require(start == SENTINEL_MODULES || isModuleEnabled(start), "GS105");
        require(pageSize > 0, "GS106");
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 moduleCount = 0;
        next = modules[start];
        while (next != address(0) && next != SENTINEL_MODULES && moduleCount < pageSize) {
            array[moduleCount] = next;
            next = modules[next];
            moduleCount++;
        }

        /**
          Because of the argument validation, we can assume that the loop will always iterate over the valid module list values
          and the `next` variable will either be an enabled module or a sentinel address (signalling the end). 
          
          If we haven't reached the end inside the loop, we need to set the next pointer to the last element of the modules array
          because the `next` variable (which is a module by itself) acting as a pointer to the start of the next page is neither 
          included to the current page, nor will it be included in the next one if you pass it as a start.
        */
        if (next != SENTINEL_MODULES) {
            next = array[moduleCount - 1];
        }
        // Set correct size of returned array
        // solhint-disable-next-line no-inline-assembly
        assembly {
            mstore(array, moduleCount)
        }
    }

    /**
     * @notice Returns true if `account` is a contract.
     * @dev This function will return false if invoked during the constructor of a contract,
     *      as the code is not actually created until after the constructor finishes.
     * @param account The address being queried
     */
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

// lib/safe-smart-account/contracts/Safe.sol

/**
 * @title Safe - A multisignature wallet with support for confirmations using signed messages based on EIP-712.
 * @dev Most important concepts:
 *      - Threshold: Number of required confirmations for a Safe transaction.
 *      - Owners: List of addresses that control the Safe. They are the only ones that can add/remove owners, change the threshold and
 *        approve transactions. Managed in `OwnerManager`.
 *      - Transaction Hash: Hash of a transaction is calculated using the EIP-712 typed structured data hashing scheme.
 *      - Nonce: Each transaction should have a different nonce to prevent replay attacks.
 *      - Signature: A valid signature of an owner of the Safe for a transaction hash.
 *      - Guard: Guard is a contract that can execute pre- and post- transaction checks. Managed in `GuardManager`.
 *      - Modules: Modules are contracts that can be used to extend the write functionality of a Safe. Managed in `ModuleManager`.
 *      - Fallback: Fallback handler is a contract that can provide additional read-only functional for Safe. Managed in `FallbackManager`.
 *      Note: This version of the implementation contract doesn't emit events for the sake of gas efficiency and therefore requires a tracing node for indexing/
 *      For the events-based implementation see `SafeL2.sol`.
 * @author Stefan George - @Georgi87
 * @author Richard Meissner - @rmeissner
 */
contract Safe is
    Singleton,
    NativeCurrencyPaymentFallback,
    ModuleManager,
    OwnerManager,
    SignatureDecoder,
    SecuredTokenTransfer,
    ISignatureValidatorConstants,
    FallbackManager,
    StorageAccessible,
    GuardManager
{
    using SafeMath for uint256;

    string public constant VERSION = "1.4.1";

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    event SafeSetup(address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler);
    event ApproveHash(bytes32 indexed approvedHash, address indexed owner);
    event SignMsg(bytes32 indexed msgHash);
    event ExecutionFailure(bytes32 indexed txHash, uint256 payment);
    event ExecutionSuccess(bytes32 indexed txHash, uint256 payment);

    uint256 public nonce;
    bytes32 private _deprecatedDomainSeparator;
    // Mapping to keep track of all message hashes that have been approved by ALL REQUIRED owners
    mapping(bytes32 => uint256) public signedMessages;
    // Mapping to keep track of all hashes (message or transaction) that have been approved by ANY owners
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    // This constructor ensures that this contract can only be used as a singleton for Proxy contracts
    constructor() {
        /**
         * By setting the threshold it is not possible to call setup anymore,
         * so we create a Safe with 0 owners and threshold 1.
         * This is an unusable Safe, perfect for the singleton
         */
        threshold = 1;
    }

    /**
     * @notice Sets an initial storage of the Safe contract.
     * @dev This method can only be called once.
     *      If a proxy was created without setting up, anyone can call setup and claim the proxy.
     * @param _owners List of Safe owners.
     * @param _threshold Number of required confirmations for a Safe transaction.
     * @param to Contract address for optional delegate call.
     * @param data Data payload for optional delegate call.
     * @param fallbackHandler Handler for fallback calls to this contract
     * @param paymentToken Token that should be used for the payment (0 is ETH)
     * @param payment Value that should be paid
     * @param paymentReceiver Address that should receive the payment (or 0 if tx.origin)
     */
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        // setupOwners checks if the Threshold is already set, therefore preventing that this method is called twice
        setupOwners(_owners, _threshold);
        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
        // As setupOwners can only be called if the contract has not been initialized we don't need a check for setupModules
        setupModules(to, data);

        if (payment > 0) {
            // To avoid running into issues with EIP-170 we reuse the handlePayment function (to avoid adjusting code of that has been verified we do not adjust the method itself)
            // baseGas = 0, gasPrice = 1 and gas = payment => amount = (payment + 0) * 1 = payment
            handlePayment(payment, 0, 1, paymentToken, paymentReceiver);
        }
        emit SafeSetup(msg.sender, _owners, _threshold, to, fallbackHandler);
    }

    /** @notice Executes a `operation` {0: Call, 1: DelegateCall}} transaction to `to` with `value` (Native Currency)
     *          and pays `gasPrice` * `gasLimit` in `gasToken` token to `refundReceiver`.
     * @dev The fees are always transferred, even if the user transaction fails.
     *      This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      - if the `gasToken` is a contract or not
     *      It is the responsibility of the caller to perform such checks.
     * @param to Destination address of Safe transaction.
     * @param value Ether value of Safe transaction.
     * @param data Data payload of Safe transaction.
     * @param operation Operation type of Safe transaction.
     * @param safeTxGas Gas that should be used for the Safe transaction.
     * @param baseGas Gas costs that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
     * @param gasPrice Gas price that should be used for the payment calculation.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @return success Boolean indicating transaction's success.
     */
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) public payable virtual returns (bool success) {
        bytes32 txHash;
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            bytes memory txHashData = encodeTransactionData(
                // Transaction info
                to,
                value,
                data,
                operation,
                safeTxGas,
                // Payment info
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // Signature info
                nonce
            );
            // Increase nonce and execute transaction.
            nonce++;
            txHash = keccak256(txHashData);
            checkSignatures(txHash, txHashData, signatures);
        }
        address guard = getGuard();
        {
            if (guard != address(0)) {
                Guard(guard).checkTransaction(
                    // Transaction info
                    to,
                    value,
                    data,
                    operation,
                    safeTxGas,
                    // Payment info
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    // Signature info
                    signatures,
                    msg.sender
                );
            }
        }
        // We require some gas to emit the events (at least 2500) after the execution and some to perform code until the execution (500)
        // We also include the 1/64 in the check that is not send along with a call to counteract potential shortings because of EIP-150
        require(gasleft() >= ((safeTxGas * 64) / 63).max(safeTxGas + 2500) + 500, "GS010");
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            uint256 gasUsed = gasleft();
            // If the gasPrice is 0 we assume that nearly all available gas can be used (it is always more than safeTxGas)
            // We only substract 2500 (compared to the 3000 before) to ensure that the amount passed is still higher than safeTxGas
            success = execute(to, value, data, operation, gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
            gasUsed = gasUsed.sub(gasleft());
            // If no safeTxGas and no gasPrice was set (e.g. both are 0), then the internal tx is required to be successful
            // This makes it possible to use `estimateGas` without issues, as it searches for the minimum gas where the tx doesn't revert
            require(success || safeTxGas != 0 || gasPrice != 0, "GS013");
            // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
            uint256 payment = 0;
            if (gasPrice > 0) {
                payment = handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
            }
            if (success) emit ExecutionSuccess(txHash, payment);
            else emit ExecutionFailure(txHash, payment);
        }
        {
            if (guard != address(0)) {
                Guard(guard).checkAfterExecution(txHash, success);
            }
        }
    }

    /**
     * @notice Handles the payment for a Safe transaction.
     * @param gasUsed Gas used by the Safe transaction.
     * @param baseGas Gas costs that are independent of the transaction execution (e.g. base transaction fee, signature check, payment of the refund).
     * @param gasPrice Gas price that should be used for the payment calculation.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @return payment The amount of payment made in the specified token.
     */
    function handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private returns (uint256 payment) {
        // solhint-disable-next-line avoid-tx-origin
        address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
        if (gasToken == address(0)) {
            // For ETH we will only adjust the gas price to not be higher than the actual used gas price
            payment = gasUsed.add(baseGas).mul(gasPrice < tx.gasprice ? gasPrice : tx.gasprice);
            require(receiver.send(payment), "GS011");
        } else {
            payment = gasUsed.add(baseGas).mul(gasPrice);
            require(transferToken(gasToken, receiver, payment), "GS012");
        }
    }

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     */
    function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures) public view {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "GS001");
        checkNSignatures(dataHash, data, signatures, _threshold);
    }

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @dev Since the EIP-1271 does an external call, be mindful of reentrancy attacks.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @param requiredSignatures Amount of required valid signatures.
     */
    function checkNSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, uint256 requiredSignatures) public view {
        // Check that the provided signature data is not too short
        require(signatures.length >= requiredSignatures.mul(65), "GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                require(keccak256(data) == dataHash, "GS027");
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= requiredSignatures.mul(65), "GS021");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "GS022");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "GS023");

                // Check signature
                bytes memory contractSignature;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(ISignatureValidator(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE, "GS024");
            } else if (v == 1) {
                // If v is 1 then it is an approved hash
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint160(uint256(r)));
                // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "GS025");
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(currentOwner > lastOwner && owners[currentOwner] != address(0) && currentOwner != SENTINEL_OWNERS, "GS026");
            lastOwner = currentOwner;
        }
    }

    /**
     * @notice Marks hash `hashToApprove` as approved.
     * @dev This can be used with a pre-approved hash transaction signature.
     *      IMPORTANT: The approved hash stays approved forever. There's no revocation mechanism, so it behaves similarly to ECDSA signatures
     * @param hashToApprove The hash to mark as approved for signatures that are verified by this contract.
     */
    function approveHash(bytes32 hashToApprove) external {
        require(owners[msg.sender] != address(0), "GS030");
        approvedHashes[msg.sender][hashToApprove] = 1;
        emit ApproveHash(hashToApprove, msg.sender);
    }

    /**
     * @notice Returns the ID of the chain the contract is currently deployed on.
     * @return The ID of the current chain as a uint256.
     */
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * @dev Returns the domain separator for this contract, as defined in the EIP-712 standard.
     * @return bytes32 The domain separator hash.
     */
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, getChainId(), this));
    }

    /**
     * @notice Returns the pre-image of the transaction hash (see getTransactionHash).
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @param safeTxGas Gas that should be used for the safe transaction.
     * @param baseGas Gas costs for that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
     * @param gasPrice Maximum gas price that should be used for this transaction.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param _nonce Transaction nonce.
     * @return Transaction hash bytes.
     */
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }

    /**
     * @notice Returns transaction hash to be signed by owners.
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @param safeTxGas Fas that should be used for the safe transaction.
     * @param baseGas Gas costs for data used to trigger the safe transaction.
     * @param gasPrice Maximum gas price that should be used for this transaction.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param _nonce Transaction nonce.
     * @return Transaction hash.
     */
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(encodeTransactionData(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce));
    }
}

// src/backdoor/WalletRegistry.sol

// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)

/**
 * @notice A registry for Safe multisig wallets.
 *         When known beneficiaries deploy and register their wallets, the registry awards tokens to the wallet.
 * @dev The registry has embedded verifications to ensure only legitimate Safe wallets are stored.
 */
contract WalletRegistry is IProxyCreationCallback, Ownable {
    uint256 private constant EXPECTED_OWNERS_COUNT = 1;
    uint256 private constant EXPECTED_THRESHOLD = 1;
    uint256 private constant PAYMENT_AMOUNT = 10e18;

    address public immutable singletonCopy;
    address public immutable walletFactory;
    IERC20 public immutable token;

    mapping(address => bool) public beneficiaries;

    // owner => wallet
    mapping(address => address) public wallets;

    error NotEnoughFunds();
    error CallerNotFactory();
    error FakeSingletonCopy();
    error InvalidInitialization();
    error InvalidThreshold(uint256 threshold);
    error InvalidOwnersCount(uint256 count);
    error OwnerIsNotABeneficiary();
    error InvalidFallbackManager(address fallbackManager);

    constructor(
        address singletonCopyAddress,
        address walletFactoryAddress,
        address tokenAddress,
        //@audit-question can initialBeneficiares be too big that it causes DOS?
        address[] memory initialBeneficiaries
    ) {
        _initializeOwner(msg.sender);

        singletonCopy = singletonCopyAddress;
        walletFactory = walletFactoryAddress;
        token = IERC20(tokenAddress);

        for (uint256 i = 0; i < initialBeneficiaries.length; ++i) {
            unchecked {
                beneficiaries[initialBeneficiaries[i]] = true;
            }
        }
    }

    function addBeneficiary(address beneficiary) external onlyOwner {
        beneficiaries[beneficiary] = true;
    }

    /**
     * @notice Function executed when user creates a Safe wallet via SafeProxyFactory::createProxyWithCallback
     *          setting the registry's address as the callback.
     */
    function proxyCreated(SafeProxy proxy, address singleton, bytes calldata initializer, uint256) external override {
        if (token.balanceOf(address(this)) < PAYMENT_AMOUNT) {
            // fail early
            revert NotEnoughFunds();
        }

        address payable walletAddress = payable(proxy);

        // Ensure correct factory and copy
        if (msg.sender != walletFactory) {
            revert CallerNotFactory();
        }

        if (singleton != singletonCopy) {
            revert FakeSingletonCopy();
        }

        // Ensure initial calldata was a call to `Safe::setup`
        if (bytes4(initializer[:4]) != Safe.setup.selector) {
            revert InvalidInitialization();
        }

        // Ensure wallet initialization is the expected
        uint256 threshold = Safe(walletAddress).getThreshold();
        if (threshold != EXPECTED_THRESHOLD) {
            revert InvalidThreshold(threshold);
        }

        address[] memory owners = Safe(walletAddress).getOwners();
        if (owners.length != EXPECTED_OWNERS_COUNT) {
            revert InvalidOwnersCount(owners.length);
        }

        // Ensure the owner is a registered beneficiary
        address walletOwner;
        unchecked {
            walletOwner = owners[0];
        }
        if (!beneficiaries[walletOwner]) {
            revert OwnerIsNotABeneficiary();
        }

        address fallbackManager = _getFallbackManager(walletAddress);
        
        if (fallbackManager != address(0)) {
            revert InvalidFallbackManager(fallbackManager);
        }

        // Remove owner as beneficiary
        beneficiaries[walletOwner] = false;

        // Register the wallet under the owner's address
        wallets[walletOwner] = walletAddress;

        // Pay tokens to the newly created wallet
        SafeTransferLib.safeTransfer(address(token), walletAddress, PAYMENT_AMOUNT);
    }

    function _getFallbackManager(address payable wallet) private view returns (address) {
        return abi.decode(
            Safe(wallet).getStorageAt(uint256(keccak256("fallback_manager.handler.address")), 0x20), (address)
        );
    }
}

