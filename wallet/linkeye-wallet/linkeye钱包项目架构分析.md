
# linkeye钱包项目架构分析

### 一.简述

linkeye钱包是对接linkeye公链的钱包项目，不能对接其他的公链。linkeye钱包是nodejs, electron和vue开发的本地桌面钱包，整个账户体系的信息都在用户自己的设备上。nodeJs是一个本地的服务，vue是渲染进程，nodejs本地服务和vue渲染进程之间通过electron的主进程和渲染进程通信机制通信。用户的账户体系数据存储在本地sqlite3数据库中。整个项目分为创建账户生成keystore模块,导出私钥模块，导入私钥模块，账户体系模块，转账记录模块，转账模块，转账确认模块。


linkeye-wallet架构图： 
    ![linkeye-wallet架构图： 
](https://github.com/guoshijiang/go-ethereum-code-analysis/blob/master/wallet/linkeye-wallet/img/linkeye-wallet.png "linkeye-wallet架构图： 
")
