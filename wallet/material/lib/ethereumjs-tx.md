
# ethereumjs-tx库介绍

这个库主要是用来签名交易的，签名完的交易通过web3发送到以太坊钱包节点；此库运行的环境ECMAScript 6（ES6）为最低环境。 在缺乏ES6支持的浏览器中，请使用垫片（如es6-shim），否则该库可能运行不起来。

## 1.安装

    npm install ethereumjs-tx

## 2.使用案例

    const EthereumTx = require('ethereumjs-tx')
    const privateKey = Buffer.from('e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109', 'hex')

    const txParams = {
      nonce: '0x00',
      gasPrice: '0x09184e72a000', 
      gasLimit: '0x2710',
      to: '0x0000000000000000000000000000000000000000', 
      value: '0x00', 
      data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
      // EIP 155 chainId - mainnet: 1, ropsten: 3
      chainId: 3
    }

    const tx = new EthereumTx(txParams)
    tx.sign(privateKey)
    const serializedTx = tx.serialize()
