
# web3js

## 1.web3js简介

web3js的以太坊提供的与节点进行通行的JavaScript库，这是Ethereum兼容的JavaScript API，它实现了通用JSON RPC规范。 它可以作为npm作为节点模块，作为可嵌入的js和作为meteor.js包使用。web3中有eth对象-web3.eth 具体来表示与以太坊区块链之间的交互。shh对象 - web3.shh表示Whisper协议的相关交互。后续我们会继续介绍其它一些web3协议中的对象。web3提供了HttpProvider和IpcProvider两中通信方式。

## 2.web3的安装

1.npm方式安装

    npm install web3
    
2.bower方式安装

    bower install web3
    
3.将web3添加到meteor中
    
    meteor add ethereum:web3
4.vanilla   

    dist./web3.min.js
    
5.yarn方式管理web3

    yarn add web3
    
6.cdn

    <script src="https://cdn.jsdelivr.net/gh/ethereum/web3.js/dist/web3.min.js"></script>

7.Component

    component install ethereum/web3.js
    
你可以根据自己的环境和自身的喜好通过以上方式来安装web3，当然如果你还有其他的方式安装，你也可以告诉我们

## 3.web3的使用

### 3.1.定义web3

1.直接通过全局命名空间使用web3对象

console.log(web3); // {eth: .., shh: ...} // it's here!

2.设置一个provider(如HttpProvider)

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}

3.设置一个provider(HttpProvider使用http的基本认证)

web3.setProvider(new web3.providers.HttpProvider('http://host.url', 0, BasicAuthUsername, BasicAuthPassword));


### 3.2.使用web3的案例

1.获取web3的版本

    var version = web3.version.api;
    console.log(version);

2.从以太坊节点上获取用户数

    var accounts = web3.eth.accounts;
    console.log(accounts);

3.从以太坊节点上获取区块数量

    var bnum = web3.eth.blockNumber;
    console.log(bnum);

4.获取0xfa319c8ea9b00513bb1a112de2073263aa92c930账户余额

    web3.eth.getBalance("0xfa319c8ea9b00513bb1a112de2073263aa
    92c930", function(err, result)
    {
       if (err == null)
       {
          console.log('~balance:' + result);
       }
       else
       {
          console.log('~balance:' + result);
       }
    });
    
5.获取交易的结果

    web3.eth.getTransaction('0x043e9bfaea7854f41e0d55121788
    51be1d2d584bd5ee339ae03cac1796b04781', function(err, 
    result)
    {
       if (err == null)
       {
          console.log('~transaction:' + result);
       }
       else
       {
          console.log('err', + err);
       }
    });

6.实现转账代码
要发起转账，需要安装一个nodeJs的模块，这个模块叫做ethereumjs-tx
代码实现如下：

    var Tx = require('ethereumjs-tx');
    var privateKey = new Buffer('7418BC72BAB71BDEB450D4AD91BA
    07C03E50B21D13B7C74E806510EAE9769475', 'hex');
    var rawTx =
    {
       nonce:'',
       gasPrice:'0x3b9aca00',
       gasLimit:'0x493e0',
       to: '0x545a05d023d746e342ab8d31e792b4a2f6e9e19e',
       value: '10',
       data: ' '
    };

    var tx = new Tx(rawTx);
    tx.sign(privateKey);

    var serializedTx = tx.serialize();
    web3.eth.sendRawTransaction('0x' + serializedTx.
    toString('hex'), function (err, hash)
    {
       console.log('交易结果：' + hash);

       if (callback && typeof(callback) === "function")
       {
          if(!err)
          {
             callback(null, hash);
          }
          else
          {
             callback(err, null);
          }
       }
    });
