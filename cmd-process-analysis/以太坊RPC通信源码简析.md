
# 以太坊RPC通信源码简析

### 1.rpc包中的client.go的功能说明

  客户端的主要功能是把请求发送到服务端，然后接收回应，再把回应传递给调用者。

### 2.rpc包中的server.go的功能说明
  
  主要实现了RPC服务端的核心逻辑。 包括RPC方法的注册， 读取请求，处理请求，发送回应等逻辑。 server的核心数据结构是Server结构体。 services字段是一个map，记录了所有注册的方法和类。 run参数是用来控制Server的运行和停止的。 codecs是一个set。用来存储所有的编码解码器，其实就是所有的连接。 codecsMu是用来保护多线程访问codecs的锁。
  
### 3.RPC包总揽

   以太坊有四种RPC。HTTP RPC、Inproc RPC、IPC RPC、WS RPC。它们主要的实现逻辑都在rpc/server.go和rpc/client.go。各自根据自己的实现方式派生自己的client实例，建立各自的net.conn通道。由于HTTP RPC是基于短链接请求，实现方式和其他的不太一样


