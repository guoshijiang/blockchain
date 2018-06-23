# BIP系列

## 1.bip21

bip21是一个兼容性的url编码库

### 1.1.使用案例

请在node环境下使用

引入依赖库 bip21
    
    var bip21 = require('bip21')
解码

    bip21.decode('bitcoin:1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH?amount=20.3&label=Foobar')
    
编码

    bip21.encode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')
    bip21.encode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', {amount: 20.3, label: 'Foobar'})
    



