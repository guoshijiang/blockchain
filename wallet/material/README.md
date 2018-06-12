
# 使用nodejs开发一个简易版的钱包的流程

### 1.生成助记词

使用bip39库，关于bip系列库的讲解，将在以后的文章中做详细说明

    const bip39 = require('bip39');

钱包的助记词一般为12个单词，下面代码生成的助记词就是12个

    let words = bip39.generateMnemonic();

接下来，再根据助记词和密码生成随机数种植

    let password = '123456';
    let seedAsHex = bip39.mnemonicToSeedHex(words, password);
    console.log("--------------random deed------------------");
    console.log(seedAsHex);
    
### 2.生成keystore,导出私钥

这里需要用到keythereum库，关于keythereum库咱们会有专门的文章介绍

      var params = { keyBytes: 32, ivBytes: 16 };
      var dk = keythereum.create(params);
      var options = {
        kdf: "pbkdf2",
        cipher: "aes-128-ctr",
        kdfparams: {
          c: 262144,
          dklen: 32,
          prf: "hmac-sha256"
        }
      };
      var keyObject = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options);
      keythereum.exportToFile(keyObject);

这里生成keystore如果想用随机数种子，那么把随机数种子变成私钥就行，导出的私钥其实就是将dk.privateKey导出给用户就行

### 3.使用web3和以太坊交互

假设咱们开发的是一个以太坊轻钱包，那么咱们得和以太坊的钱包节点进行交互，因此我需要使用到web3js。

引入web3js

    var Web3 = require("web3");
    
    if (typeof web3 !== 'undefined')
    {
        web3 = new Web3(web3.currentProvider);
    }
    else
    {
        web3 = new Web3(new Web3.providers.HttpProvider("http://10.23.1.209:8545"));
    }

### 4.获取账户余额

    web3.eth.getBalance("0x68db18a9cd87403c39e84467b332195b43fc33b5", function(err, result)
    {
        if (err == null)
        {
            console.log('~balance Ether:' +web3.fromWei(result, "ether"));
        }
        else
        {
            console.log('~balance Ether:' + web3.fromWei(result, "ether"));
        }
    });

### 5.获取交易的nonce

    web3.eth.getTransactionCount("0x68db18a9cd87403c39e84467b332195b43fc33b5", function (err, result)
    {
        if (err == null)
        {
            console.log('nonce:' + result);
        }
        else
        {
            console.log('nonce:' + result);
        }
    });

### 6.发起转账

转账需要使用到ethereumjs-tx库，对交易进行签名，关于ethereumjs-tx库，请参阅咱们相关的文章

    var Tx = require('ethereumjs-tx');
    var privateKey = new Buffer.from('0f8e7b1b99f49d1d94ac42084216a95fe5967caec6bba35c62c911f6c4eafa95', 'hex')

    var rawTx = {
        subId:'0x0000000000000000000000000000000000',
        nonce: '0x1',
        gasPrice: '0x1a13b8600',
        gas: '0xf4240',
        to: '0x82aeb528664bb153d2114ae7ca4ef118ef1e7a98',
        value: '0x8ac7230489e80000',
        data:'0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675',
        //chainId:"10"
    };

    var tx = new Tx(rawTx);
    tx.sign(privateKey);

    var serializedTx = tx.serialize();

    if (tx.verifySignature())
    {
        console.log('Signature Checks out!')
    }

    web3.eth.sendRawTransaction('0x' + serializedTx.toString('hex'), function(err, hash) {
        if (!err)
        {
            console.log("hash:" + hash); // "0x7f9fade1c0d57a7af66ab4ead79fade1c0d57a7af66ab4ead7c2c2eb7b11a91385"
        }
        else
        {
            console.log(err);
        }
    });
