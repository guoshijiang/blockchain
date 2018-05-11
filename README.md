# 以太坊源码解析

## 代码目录解析

* account  					       该包实现了高层级的Ethereum账号管理
* account/abi 				     该包实现了Ethereum的ABI(应用程序二进制接口)
* account/abi/bind 			   该包生成Ethereum合约的Go绑定
* account/abi/bind/backends	        --
* account/keystore 		      实现了Secp256k1私钥的加密存储
* account/usbwallet			    该包实现了支持USB硬件钱包

* btm						            该包实现了二叉merkle树

* cmd/abigen				
* cmd/bootnode				该节点为Ethereum发现协议运行一个引导节点
* cmd/ethkey
* cmd/evm					执行EVM代码片段
* cmd/faucet				faucet是以太faucet支持的轻量级客户
* cmd/geth					geth是Ethereum的官方客户端命令行
* cmd/p2psim				p2psim为客户端命令行模拟	HTTP API
* cmd/puppeth				puppeth是一个命令组装和维护私人网路
* cmd/rlpdump				rlpdump能更好的打印出RLP格式的数据
* cmd/swarm				bzzhash命令能够更好的计算出swarm哈希树
* cmd/utils					为Go-Ethereum命令提供说明
* cmd/wnode				
* common					包含一些帮助函数
* common/bitutil				该包实现快速位操作
* common/compiler			包装了Solity编译器可执行文件
* common/fdllimit				
* common/hexutil				以0x为前缀的十六进制编码
* common/math				数学工具
* common/number			
* compression/rle				实现run-length encoding编码用于Ethereum数据
* comsensus				实现了不同以太共识引擎
* comsensus/clique			实现了权威共识引擎
* comsensus/ethash			发动机工作的共识ethash证明
* comsensus/misc			
* console					
* contracts/chequebook		'支票薄'以太智能合约
* contracts/chequebook/contract    
* contracts/ens				
* contracts/ens/contract 		
* core 						实现以太合约接口
* core/asm					汇编和反汇编接口
* core/bloombits				Bloom过滤批量数据
* core/state					封装在以太状态树之上的一种缓存结构
* core/types					以太合约支持的数据类型
* core/vm					以太虚拟机
* core/vm/runtime			一种用于执行EVM代码的基本执行模型
* crypto					
* crypto/bn256				最优的ATE配对在256位Barreto-Naehrig曲线上
* crypto/bn256/cloudflare		在128位安全级别上的特殊双线性组
* crypto/bn256/google			在128位安全级别上的特殊双线性组
* crypto/ecies				
* crypto/randentropy			
* crypto/secp256k1 			封装比特币secp256k1的C库
* crypto/sha3				Sha-3固定输出长度散列函数 and 由FIPS-202定义的抖动变量输出长度散列函数

* dashboard				        

* eth 						以太坊协议
* ethclient					以太坊RPC AIP客户端
* ethdb 					
* eth/downloader				手动全链同步
* eth/fetcher				基于块通知的同步
* eth/filters					用于区块，交易和日志事件的过滤
* eth/gasprice				
* eth/stats					网络统计报告服务
* eth/tracers				收集JavaScript交易追踪
* event					处理时时事件的费用
* event/filter 				事件过滤

* internal/build				
* internal/cmdtest			        
* internal/debug				调试接口Go运行时调试功能
* internal/ethapi				常用的以太坊API函数
* internal/guide				小测试套件，以确保开发指南工作中的代码段正常运行
* internal/jsre				JavaScript执行环境
* internal/jsre/deps			控制台JavaScript依赖项Go嵌入
* internal/web3ext			geth确保web3.js延伸

* les						轻量级Ethereum子协议
* les/flowcontrol				客户端流程控制机制
* light						EtalumLight客户端实现按需检索能力的状态和链对象

* log						log输出日志
* log/term                                    --

* metrics					Coda Hale度量库的Go端口
* metrics/exp 				表达式相关操作
* metrics/influxdb			        
* metrics/librato				
* miner					以太坊块创建和挖矿
* mobile					geth的移动端API

* node						设置多维接口节点

* p2p 						p2p网络协议
* p2p/discover				节点发现协议
* p2p/discv5				RLPx v5主题相关的协议
* p2p/enr 					实现EIP-778中的以太坊节点记录
* p2p/nat					提供网络端口映射协议的权限
* p2p/netutil 				网络包拓展
* p2p/protocols 				p2p拓展
* p2p/simulations				实现模拟p2p网络
* p2p/simulations/adapters	        
* p2p/simulations/examples	        
* p2p/testing				
* params					

* rlp 						RLP系列化格式
* rpc 						通过网络或者I/O链接来访问接口

* swarm					
* swarm/api 				
* swarm/api/client 			
* swarm/api/http 				HTML格式错误的处理
* swarm/fuse				
* swarm/metrics 				
* swarm/network 				
* swarm/network/kademlia 		
* swarm/services/swap			
* swarm/services/swap/swap 	
* swarm/storage				
* swarm/testutil				

* tests						以太坊JSON测试
* trie						Merkle Patricia树实现

* vendor/gopkg.in/check.v1 	Go更深的测试
* vendor/gopkg.in/urfave/cli.v1 Go命令行应用的框架

* whisper/mailserver		
* whisper/shhclient			
* whisper/whisperv2			Whisper Poc-1实现
* whisper/whisperv5			Whisper协议(版本5)
* whisper/whisperv6			


