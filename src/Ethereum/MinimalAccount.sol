// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Minimal ERC-4337 Smart Account
 * @author —
 *
 * @notice
 * A minimal implementation of an Account Abstraction wallet compatible with
 * the ERC-4337 EntryPoint contract.
 *
 * Responsibilities:
 * - Validate UserOperation signatures
 * - Prefund gas payments to the EntryPoint
 * - Execute arbitrary calls on behalf of the owner
 *
 * Security Model:
 * - Immutable EntryPoint
 * - Owner-based signature validation
 * - Execution restricted to EntryPoint
 *
 * This contract is intentionally minimal for learning and extension.
 */


import {IAccount} from "@account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    ////////////////////////////////////////////////////////////////
    //                           STATE
    ////////////////////////////////////////////////////////////////

    /// @notice Immutable trusted EntryPoint
    IEntryPoint public immutable I_ENTRY_POINT;

    ////////////////////////////////////////////////////////////////
    //                           ERRORS
    ////////////////////////////////////////////////////////////////

    error MinimalAccount_NotEntryPoint();
    error MinimalAccount_NotEntryPointOrOwner();
    error MinimalAccount_PrefundFailed();
    error MinimalAccount_CallFailed(bytes);

    ////////////////////////////////////////////////////////////////
    //                        CONSTRUCTOR
    ////////////////////////////////////////////////////////////////

    constructor(address entryPoint) Ownable(msg.sender) {
        I_ENTRY_POINT = IEntryPoint(entryPoint);
    }

    ////////////////////////////////////////////////////////////////
    //                         MODIFIERS
    ////////////////////////////////////////////////////////////////

    modifier requireFromEntryPoint() {
        _requireFromEntryPoint();
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        _requireFromEntryPointOrOwner();
        _;
    }

    receive() external payable {}

    ////////////////////////////////////////////////////////////////
    //                    Wrapped Modifier logic
    ////////////////////////////////////////////////////////////////
    /** * @notice Wrapped modifier logic to allow both EntryPoint and owner calls. * @dev Used for functions that can be called by either the EntryPoint or the owner. */

    function _requireFromEntryPoint() internal view {
        if (msg.sender != address(I_ENTRY_POINT)) {
            revert MinimalAccount_NotEntryPoint();
        }
    }

    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(I_ENTRY_POINT) && msg.sender != owner()) {
            revert MinimalAccount_NotEntryPointOrOwner();
        }
    }

    ////////////////////////////////////////////////////////////////
    //                    ERC-4337 VALIDATION
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Called by EntryPoint to validate a UserOperation.
     * @dev Must return validationData encoded as uint256.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external requireFromEntryPoint returns (uint256 validationData) {
        // Validate signature
        validationData = _validateSignature(userOp, userOpHash);

        // Prefund EntryPoint if required
        _payPrefund(missingAccountFunds);
    }

    ////////////////////////////////////////////////////////////////
    //                     INTERNAL LOGIC
    ////////////////////////////////////////////////////////////////

    function _payPrefund(uint256 _missingAccountFunds) internal {
        if (_missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: _missingAccountFunds
            }("");

            if (!success) {
                revert MinimalAccount_PrefundFailed();
            }
        }
        
    }

    /**
     * @notice Validates that the UserOperation was signed by the owner.
     * @dev Uses EIP-191 signed message hash.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            userOpHash
        );

        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);

        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    ////////////////////////////////////////////////////////////////
    //                       EXECUTION
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Executes a call on behalf of the account.
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata funcData
    ) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(funcData);

        if (!success) {
            revert MinimalAccount_CallFailed(result);
        }
    }

    ////////////////////////////////////////////////////////////////
    //                         GETTERS
    ////////////////////////////////////////////////////////////////

    function getEntryPoint() external view returns (address) {
        return address(I_ENTRY_POINT);
    }
}
