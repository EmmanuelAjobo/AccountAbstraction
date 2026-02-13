// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/Script.sol";

import {MinimalAccount} from "src/Ethereum/MinimalAccount.sol";
import {DeployMinimal} from "script/DeployMinimal.sol";
import {HelperConfig} from "script/HelperConfig.sol";
import {SendPackedUserOp} from "script/SendPackedUserOp.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {
    PackedUserOperation
} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// -
contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    SendPackedUserOp sendPackedUserOp;
    ERC20Mock usdc;

    uint256 constant AMOUNT = 21 ether;
    address constant FOUNDRY_DEFAULT_WALLET =
        0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;

    address user1 = makeAddr("User1");

    function setUp() public {
        DeployMinimal deployMinimal = new DeployMinimal();
        (helperConfig, minimalAccount) = deployMinimal.deployMinimalAccount();
        sendPackedUserOp = new SendPackedUserOp();
        usdc = new ERC20Mock();
    }

    // What exactly do we want to test ?
    // We want to test that
    // Someone can sign a data
    // The data can go through the alt mempool
    // Go through the entrypoint
    // And then have My contract do some functions

    //USDC mint

    // msg.sender => Minimal Account
    // approve some amount
    // USDC contract
    // Come from the entry point

    function testOwnerCanExecuteCommands() public {
        //Arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        ); // Learn

        // Act
        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, funcData);

        // Assert

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testNonOwnerCannotExecuteCommands() public {
        //Arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        ); // Learn

        // Act
        vm.prank(user1);
        vm.expectRevert(
            MinimalAccount.MinimalAccount_NotEntryPointOrOwner.selector
        );
        minimalAccount.execute(dest, value, funcData);

        // Assert

        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
    }

    // We need to test we are signing correctly,
    // We need to code our calldata that tells the entry point contract to call our contract and then have our contract  call USDC
    function testRecoverSignedOp() public {
        // Arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        ); // Learn
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        ); // Learn

        PackedUserOperation memory userOp = sendPackedUserOp
            .generateSignedUSerOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );

        bytes32 userOpHash = IEntryPoint(helperConfig.getConfig().entryPoint)
            .getUserOpHash(userOp);
        // Act
        address actualSigner = ECDSA.recover(
            userOpHash.toEthSignedMessageHash(),
            userOp.signature
        );

        // Assert

        assertEq(actualSigner, minimalAccount.owner());
    }

    // To test Validate User Ops
    // for us to start testing this we are going create PackedUserOperation
    // get the hash of the userOp
    // figure out the Missing Account funds (How mush it costs)

    // For us to test for validation of User Ops, We need to test creation of packed user Ops

    // 1. Sign user op
    // 2. Call validate userOps
    // 3. Assert the return is correct

    function testValidationOfUserOps() public {
        /**
         * ===============================================================
         *                         TEST GOAL
         * ===============================================================
         *
         * Verify that the smart account correctly validates a properly
         * signed UserOperation when called by the EntryPoint.
         *
         * This is NOT testing execution.
         * This is testing AUTHORIZATION.
         *
         * Think of validateUserOp as the wallet’s security gate.
         * If this gate is weak → the wallet is already compromised.
         */

        // ===============================================================
        // Arrange
        // ===============================================================

        // Always verify initial state.
        // Strong tests anchor themselves in known conditions.
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);

        address dest = address(usdc);
        uint256 value = 0;

        /**
         * Encode the target function call.
         *
         * LESSON:
         * Smart accounts operate on raw calldata.
         * If you cannot reason about calldata,
         * auditing account abstraction becomes very difficult.
         */
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        /**
         * We now encode the smart account execution itself.
         *
         * Execution is nested:
         *
         * EntryPoint → SmartAccount.execute → Token.mint
         *
         * Always visualize the call stack when auditing.
         */
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        );

        /**
         * Generate a signed UserOperation.
         *
         * SECURITY LESSON:
         * The signature is the highest authority in ERC-4337.
         * msg.sender is irrelevant during validation.
         */
        PackedUserOperation memory userOp = sendPackedUserOp
            .generateSignedUSerOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );

        /**
         * BEST PRACTICE:
         * Always derive the hash from EntryPoint.
         *
         * Never manually reconstruct this hash in production code.
         * One encoding mismatch can permanently brick signatures.
         */
        bytes32 userOpHash = IEntryPoint(helperConfig.getConfig().entryPoint)
            .getUserOpHash(userOp);

        // ===============================================================
        // Act
        // ===============================================================

        /**
         * CRITICAL SECURITY RULE:
         * validateUserOp MUST only be callable by EntryPoint.
         *
         * If anyone else can call it,
         * attackers may bypass bundler validation logic.
         */
        vm.prank(helperConfig.getConfig().entryPoint);

        /**
         * missingAccountFunds represents how much ETH
         * EntryPoint expects the wallet to prefund.
         *
         * For validation testing, zero is acceptable because
         * we are verifying signature correctness — not gas economics.
         */
        uint256 validationData = minimalAccount.validateUserOp(
            userOp,
            userOpHash,
            0
        );

        // ===============================================================
        // Assert
        // ===============================================================

        /**
         * validationData == 0 means:
         *
         * ✅ Signature is valid
         * ✅ Nonce is acceptable
         * ✅ No time-range restrictions failed
         *
         * Any non-zero value encodes validation failure metadata.
         */
        assertEq(validationData, 0);
    }

    function testEntryPointCanExecuteCommands() public {
        /**
         * ===============================================================
         *                      TEST GOAL
         * ===============================================================
         *
         * Prove that a properly signed UserOperation can travel through:
         *
         * Bundler → EntryPoint → Smart Account → Target Contract
         *
         * And successfully execute arbitrary logic.
         *
         * This is the core execution pipeline of ERC-4337.
         */

        // ===============================================================
        // Arrange
        // ===============================================================

        // Always begin by asserting the initial state.
        // Tests without strong preconditions are unreliable.
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);

        address dest = address(usdc);
        uint256 value = 0;

        /**
         * LESSON:
         * encodeWithSelector creates low-level calldata exactly how the EVM expects it.
         * This is equivalent to calling:
         *
         * usdc.mint(address(minimalAccount), AMOUNT);
         *
         * but gives us surgical control over execution.
         */
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        /**
         * The smart account will execute this call.
         *
         * IMPORTANT SECURITY MODEL:
         * The smart account is NOT the authority.
         * The signature is the authority.
         */
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        );

        /**
         * Generate a signed UserOperation.
         *
         * This simulates a real wallet signing an intent
         * that will later be submitted by ANY bundler.
         */
        PackedUserOperation memory userOp = sendPackedUserOp
            .generateSignedUSerOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );

        /**
         * ===============================================================
         * CRITICAL LESSON — ENTRYPOINT DEPOSITS
         * ===============================================================
         *
         * ERC-4337 DOES NOT use the wallet's raw ETH balance
         * to pay for gas.
         *
         * Instead it uses a separate ledger inside EntryPoint.
         *
         * Many developers fund the wallet and wonder why
         * handleOps reverts.
         */

        vm.deal(minimalAccount.owner(), 10 ether);
        vm.deal(FOUNDRY_DEFAULT_WALLET, 10 ether);



        vm.prank(minimalAccount.owner());
        IEntryPoint(helperConfig.getConfig().entryPoint).depositTo{
            value: 10 ether
        }(address(minimalAccount));

        /**
         * ===============================================================
         * Act
         * ===============================================================
         *
         * We impersonate a random bundler.
         *
         * SECURITY INSIGHT:
         * Bundlers are transport layers.
         * They are NOT trusted actors.
         *
         * If your wallet depends on msg.sender,
         * it is already vulnerable.
         */

        PackedUserOperation[] memory userOpList = new PackedUserOperation[](1);
        userOpList[0] = userOp;

console2.log("Start");

        vm.startPrank(FOUNDRY_DEFAULT_WALLET);
        IEntryPoint(helperConfig.getConfig().entryPoint).handleOps(
            userOpList,
            payable(FOUNDRY_DEFAULT_WALLET)
        );
        vm.stopPrank();


        

        // ===============================================================
        // Assert
        // ===============================================================

        /**
         * Always assert the final state.
         *
         * A test that only checks "no revert"
         * is not verifying behavior.
         */
        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }
}
