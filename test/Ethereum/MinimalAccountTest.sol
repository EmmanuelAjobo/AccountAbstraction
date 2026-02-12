// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MinimalAccount} from "src/Ethereum/MinimalAccount.sol";
import {DeployMinimal} from "script/DeployMinimal.sol";
import {HelperConfig} from "script/HelperConfig.sol";
import {SendPackedUserOp} from "script/SendPackedUserOp.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";


// -
contract MinimalAccountTest is Test {

    using MessageHashUtils for bytes32;



    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    SendPackedUserOp sendPackedUserOp;
    ERC20Mock usdc;

    uint256 constant AMOUNT = 21 ether;
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

        PackedUserOperation memory UserOp = sendPackedUserOp.generateSignedUSerOperation(executeCallData, helperConfig.getConfig());

        bytes32 userOpHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(UserOp);
        // Act
        address actualSigner = ECDSA.recover(userOpHash.toEthSignedMessageHash(), UserOp.signature);


        // Assert

        assertEq(actualSigner, minimalAccount.owner());
    }

    // To test Validate User Ops
    // for us to start testing this we are going create PackedUserOperation
    // get the hash of the userOp
    // figure out the Missing Account funds (How mush it costs)

    // For us to test for validation of User Ops, We need to test creation of packed user Ops

    function testValidationOfUserOps() public {}
}
