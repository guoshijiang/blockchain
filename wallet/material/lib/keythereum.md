# Keythereum库介绍

Keythereum是一个生成，导入和导出以太坊keys的一个javascript工具。这个库提供了一中在本地或者web钱包中使用相同的账户。它可以用于可验证的冷库钱包。

Keythereum使用相同的密钥派生函数（PBKDF2-SHA256或scrypt），对称密码（AES-128-CTR或AES-128-CBC）和消息验证代码作为geth。 您可以将生成的密钥导出到文件，将其复制到数据目录的密钥库中，并立即在您的本地Ethereum客户端中使用它。

注意：从版本0.5.0开始，keythereum的加密和解密函数都会返回缓冲区而不是字符串。 对于任何直接使用这些功能的人来说，这是一个突破性改变！

## 1.安装

    npm install keythereum

当然运行上面的命令，你需要安装nodejs，关于nodejs的安装，你可以选择自己喜欢的方式去进行安装

## 2.使用

在nodejs中使用keythereum，你需要引入它，使用关键字require

    var keythereum = require("keythereum");

压缩文件dist/keythereum.min.js在浏览器中使用时。 包只需将keythereum对象附加到窗口即可：

    <script src="dist/keythereum.min.js" type="text/javascript"></script>

### 2.1.产生key

生成一个新的随机私钥（256位），以及密钥派生函数使用的salt（256位），以及用于AES-128-CTR加密密钥的初始化向量（128位）。 如果传递一个回调函数，create是异步的，否则是同步的。

    var params = { keyBytes: 32, ivBytes: 16 };

    //synchronous
    var dk = keythereum.create(params);
    // dk:
    {
        privateKey: <Buffer ...>,
        iv: <Buffer ...>,
        salt: <Buffer ...>
    }

    //asynchronous
    keythereum.create(params, function (dk) {
        // do stuff!
    });
    
### 2.2.导出key

您需要指定密码和（可选）密钥派生函数。 如果未指定，则使用PBKDF2-SHA256来派生AES密钥。

    var password = "wheethereum";
    var kdf = "pbkdf2"; 

转储功能用于将密钥信息导出到密钥存储“秘密存储”格式。 如果提供回调函数作为要转储的第六个参数，则它将异步运行：

    // Note: if options is unspecified, the values in keythereum.constants are used.
    var options = {
      kdf: "pbkdf2",
      cipher: "aes-128-ctr",
      kdfparams: {
        c: 262144,
        dklen: 32,
        prf: "hmac-sha256"
      }
    };

    // synchronous
    var keyObject = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options);
    // keyObject:
    {
      address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
      Crypto: {
        cipher: "aes-128-ctr",
        ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        cipherparams: {
          iv: "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
        kdf: "pbkdf2",
        kdfparams: {
          c: 262144,
          dklen: 32,
          prf: "hmac-sha256",
          salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        }
      },
      id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
      version: 3
    }

    // asynchronous
    keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options, function (keyObject) {
      // do stuff!
    });

dump创建一个对象而不是JSON字符串。 在Node中，exportToFile方法提供了一种将此格式化的密钥对象导出到文件的简单方法。 它在密钥库子目录中创建一个JSON文件，并使用geth的当前文件命名约定（ISO时间戳与密钥的派生Ethereum地址连接）。

    keythereum.exportToFile(keyObject);

成功导出密钥后，您将看到如下消息：

    Saved to file:
    keystore/UTC--2015-08-11T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b

    To use with geth, copy this file to your Ethereum keystore folder
    (usually ~/.ethereum/keystore).
    

### 2.3.导出key

从geth的keystore导入密钥只能在Node上完成。 JSON文件被解析成与上面的keyObject具有相同结构的对象。

    // Specify a data directory (optional; defaults to ~/.ethereum)
    var datadir = "/home/jack/.ethereum-test";

    // Synchronous
    var keyObject = keythereum.importFromFile(address, datadir);

    // Asynchronous
    keythereum.importFromFile(address, datadir, function (keyObject) {
      // do stuff
    });

这已经过版本3和版本1的测试，但没有版本2的密钥。 （如果有的话，请给我一个版本2的keystore文件，这样我就可以测试它！）

    // synchronous
    var privateKey = keythereum.recover(password, keyObject);
    // privateKey:
    <Buffer ...>

    // Asynchronous
    keythereum.recover(password, keyObject, function (privateKey) {
      // do stuff
    });


