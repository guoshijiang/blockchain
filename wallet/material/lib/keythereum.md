# Keythereum库介绍

Keythereum是一个生成，导入和导出以太坊keys的一个javascript工具。这个库提供了一中在本地或者web钱包中使用相同的账户。

Keythereum is a JavaScript tool to generate, import and export Ethereum keys. This provides a simple way to use the same account locally and in web wallets. It can be used for verifiable cold storage wallets.
。
Keythereum uses the same key derivation functions (PBKDF2-SHA256 or scrypt), symmetric ciphers (AES-128-CTR or AES-128-CBC), and message authentication codes as geth. You can export your generated key to file, copy it to your data directory's keystore, and immediately start using it in your local Ethereum client.

Note: starting in version 0.5.0, keythereum's encrypt and decrypt functions both return Buffers instead of strings. This is a breaking change for anyone using these functions directly!
