# Keythereum库介绍

Keythereum是一个生成，导入和导出以太坊keys的一个javascript工具。这个库提供了一中在本地或者web钱包中使用相同的账户。它可以用于可验证的冷库钱包。

Keythereum使用相同的密钥派生函数（PBKDF2-SHA256或scrypt），对称密码（AES-128-CTR或AES-128-CBC）和消息验证代码作为geth。 您可以将生成的密钥导出到文件，将其复制到数据目录的密钥库中，并立即在您的本地Ethereum客户端中使用它。

注意：从版本0.5.0开始，keythereum的加密和解密函数都会返回缓冲区而不是字符串。 对于任何直接使用这些功能的人来说，这是一个突破性改变！
