## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

### stargate合约集成
```
1.部署sepolia链的adapter
forge script script/AntStrargateAdapter.s.sol --rpc-url https://sepolia.drpc.org --broadcast
2.部署arb-sepolia链的adapter
forge script script/AntStrargateAdapterARB.s.sol --rpc-url https://arbitrum-sepolia.drpc.org --broadcast 
3.执行桥合约操作
forge script script/Bridge.s.sol --rpc-url https://sepolia.drpc.org --broadcast
```

### stargate API

api入口[https://scan-testnet.layerzero-api.com/v1/swagger]

```
curl -X 'GET' \
  'https://scan-testnet.layerzero-api.com/v1/messages/tx/0xbb879586c6c36a898bbcd9a8f2bfe0f8caa55c035e21bb9da4b06177c138b2d8' \
  -H 'accept: application/json'
```

```
{
  "data": [
    {
      "pathway": {
        "srcEid": 40161,
        "dstEid": 40231,
        "sender": {
          "address": "0xfb112f7fc5725de9f630abb23e4916d6fd7526d3",
          "id": "stargate",
          "name": "Stargate",
          "chain": "sepolia"
        },
        "receiver": {
          "address": "0x657c13e8668b4ed33e524e3f8bd8559667e3eb9b",
          "id": "stargate",
          "name": "Stargate",
          "chain": "arbitrum-sepolia"
        },
        "id": "40161-40231-0xfb112f7fc5725de9f630abb23e4916d6fd7526d3-0x657c13e8668b4ed33e524e3f8bd8559667e3eb9b",
        "nonce": 267
      },
      "source": {
        "status": "SUCCEEDED",
        "tx": {
          "txHash": "0xd8c0af4a3399ace26932a26e117df6c61e6a4b89f0710e572002a8bf4097bc12",
          "blockHash": "0xcd17354518c5b47fc2957c42164bf530c908b65390e6f6cabdb8ede5a69281cb",
          "blockNumber": "7941861",
          "blockTimestamp": 1742468904,
          "from": "0xc6b7926ad8d58b95c23cae9e92854532ff775678",
          "payload": "0x010001000000000000000000000000f6d79f80758029d8957ee4028fc0156ebeb3b75100000000000f4226",
          "readinessTimestamp": 1742468928,
          "options": {
            "lzReceive": {
              "gas": "150000",
              "value": "0"
            },
            "ordered": false
          }
        }
      },
      "destination": {
        "nativeDrop": {
          "status": "N/A"
        },
        "lzCompose": {
          "status": "N/A"
        },
        "tx": {
          "txHash": "0xbb879586c6c36a898bbcd9a8f2bfe0f8caa55c035e21bb9da4b06177c138b2d8",
          "blockHash": "0x0136d452bb07410911defe06a07483449eab60523450340536273d1ba79d715d",
          "blockNumber": 134103571,
          "blockTimestamp": 1742468995
        },
        "status": "SUCCEEDED"
      },
      "verification": {
        "dvn": {
          "dvns": {
            "0x53f488e93b4f1b60e8e83aa374dbe1780a1ee8a8": {
              "txHash": "0x8c160297b2c6090950005c4c15e183a370f2348b965e1dbb86498185760141cd",
              "blockHash": "0xaf78b582bf23abba372f354af6ac136d3c41562361f5ef00c0d02ccb88b39023",
              "blockNumber": 134103466,
              "blockTimestamp": 1742468967,
              "proof": {
                "packetHeader": "0x01000000000000010b00009ce1000000000000000000000000fb112f7fc5725de9f630abb23e4916d6fd7526d300009d27000000000000000000000000657c13e8668b4ed33e524e3f8bd8559667e3eb9b",
                "payloadHash": "0x32920e015872cbceda5fff99cac63313fc212b4a77ded3b50fc3e5bae0f854b8"
              },
              "optional": false,
              "status": "SUCCEEDED"
            }
          },
          "status": "SUCCEEDED"
        },
        "sealer": {
          "tx": {
            "txHash": "0xae9a5e13cf9e4769a21d39cf1f4243b7d2b7a019bf41e358bb78269bcd30df4f",
            "blockHash": "0xa33b4cd59cdccbec5d288818647cff4ee2eb4b9a179772c0117d7c8bd2d204db",
            "blockNumber": 134103505,
            "blockTimestamp": 1742468977
          },
          "status": "SUCCEEDED"
        }
      },
      "guid": "0xa5b53ad0b8f5d8eeaa53c01f355b8efffe6b0cb074a94133d7e6d043e6bb8e12",
      "config": {
        "error": false,
        "receiveLibrary": "0x75Db67CDab2824970131D5aa9CECfC9F69c69636",
        "sendLibrary": "0xcc1ae8Cf5D3904Cef3360A9532B477529b177cCE",
        "inboundConfig": {
          "confirmations": 2,
          "requiredDVNCount": 1,
          "optionalDVNCount": 0,
          "optionalDVNThreshold": 0,
          "requiredDVNs": [
            "0x53f488e93b4f1b60e8e83aa374dbe1780a1ee8a8"
          ],
          "requiredDVNNames": [
            "LayerZero Labs"
          ],
          "optionalDVNs": [],
          "optionalDVNNames": []
        },
        "outboundConfig": {
          "confirmations": 2,
          "requiredDVNCount": 1,
          "optionalDVNCount": 0,
          "optionalDVNThreshold": 0,
          "requiredDVNs": [
            "0x8eebf8b423b73bfca51a1db4b7354aa0bfca9193"
          ],
          "requiredDVNNames": [
            "LayerZero Labs"
          ],
          "optionalDVNs": [],
          "optionalDVNNames": [],
          "executor": "0x718B92b5CB0a5552039B593faF724D182A881eDA"
        },
        "ulnSendVersion": "V302",
        "ulnReceiveVersion": "V302"
      },
      "status": {
        "name": "DELIVERED",
        "message": "Executor transaction confirmed"
      },
      "created": "2025-03-20T11:09:15.000Z",
      "updated": "2025-03-20T11:09:59.000Z"
    }
  ]
}
```

检查整体交易的status, name=DELIVERED message=Executor transaction confirmed
检查source, status=SUCCESS + from + payload(toAddress+Amount)