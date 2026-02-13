// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {HelperConfig} from "script/HelperConfig.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";



// We need to generate the signature in the packed user Ops
// For this we need a script


contract SendPackedUserOp is Script {

    using MessageHashUtils for bytes32;

    function run()  public {}

    function generateSignedUSerOperation(bytes memory callData, HelperConfig.NetworkConfig memory config, address minimalAcc)  public view returns(PackedUserOperation memory){

        uint256 nonce = IEntryPoint(config.entryPoint).getNonce(minimalAcc, 0);

        // 1. Generate the unsigned data
        PackedUserOperation memory userOp =  _generateUnsignedUserOp(callData, minimalAcc, nonce);

        // 2. Get the userOp hash
        bytes32 userOpHash = IEntryPoint(config.entryPoint).getUserOpHash(userOp);  
        // from openzepllin
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // 3. Then sign the digest and return packed op
        // vm.sign(vm.envUint(PRIVATE_KEY), digest);

        // If you have a private key unlocked

        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        // If we are on a local chain
        if (block.chainid == 31337){
            (v, r, s ) = vm.sign(ANVIL_DEFAULT_KEY, digest);
        } else {
        // foundry will check if it has that key unlocked for that address
            (v, r, s)= vm.sign(config.account, digest);
        }


        userOp.signature = abi.encodePacked(r, s, v); // NOTE THE ORDER r s v

        return userOp;
    }

    // This is gonna generate the list of the packed user op except from the signature.
    function _generateUnsignedUserOp(bytes memory callData, address sender, uint256 nonce) internal pure returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 16777216;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;


        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: bytes(""),
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: verificationGasLimit,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
    }

}

