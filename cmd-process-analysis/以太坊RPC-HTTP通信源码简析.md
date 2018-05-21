
# 以太坊RPC-HTTP通信源码简析

### 1.rpc包中的client.go的功能说明

  客户端的主要功能是把请求发送到服务端，然后接收回应，再把回应传递给调用者。

### 2.rpc包中的server.go的功能说明
  
  主要实现了RPC服务端的核心逻辑。 包括RPC方法的注册， 读取请求，处理请求，发送回应等逻辑。 server的核心数据结构是Server结构体。 services字段是一个map，记录了所有注册的方法和类。 run参数是用来控制Server的运行和停止的。 codecs是一个set。用来存储所有的编码解码器，其实就是所有的连接。 codecsMu是用来保护多线程访问codecs的锁。
  
### 3.RPC包总揽

   以太坊有四种RPC。HTTP RPC、Inproc RPC、IPC RPC、WS RPC。它们主要的实现逻辑都在rpc/server.go和rpc/client.go。各自根据自己的实现方式派生自己的client实例，建立各自的net.conn通道。由于HTTP RPC是基于短链接请求，实现方式和其他的不太一样

### 4.启动的过程命令

https://github.com/guoshijiang/go-ethereum-code-analysis/blob/master/cmd-process-analysis/img/4.png


在上面的图片中，使用linkeye --rpc来启动的原因是代码已被本人修改

### 5.代码过程解析

RPC相关的命令行

    RPCEnabledFlag = cli.BoolFlag{
        Name:  "rpc",
        Usage: "Enable the HTTP-RPC server",
      }
      RPCListenAddrFlag = cli.StringFlag{
        Name:  "rpcaddr",
        Usage: "HTTP-RPC server listening interface",
        Value: node.DefaultHTTPHost,
      }
      RPCPortFlag = cli.IntFlag{
        Name:  "rpcport",
        Usage: "HTTP-RPC server listening port",
        Value: node.DefaultHTTPPort,
      }
      RPCCORSDomainFlag = cli.StringFlag{
        Name:  "rpccorsdomain",
        Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
        Value: "",
      }
      RPCVirtualHostsFlag = cli.StringFlag{
        Name:  "rpcvhosts",
        Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
        Value: strings.Join(node.DefaultConfig.HTTPVirtualHosts, ","),
      }
      RPCApiFlag = cli.StringFlag{
        Name:  "rpcapi",
        Usage: "API's offered over the HTTP-RPC interface",
        Value: "",
      }
      
执行linkeye --rpc命令后，先启动P2P通信，由于我们这里讲解的是RPC通信，故而P2P通信的内容咱们这边先略过，通过调用`startRPC`去启动RPC通信

        func (n *Node) Start() error {
          n.lock.Lock()
          defer n.lock.Unlock()

          // Short circuit if the node's already running
          if n.server != nil {
            return ErrNodeRunning
          }
          if err := n.openDataDir(); err != nil {
            return err
          }

          // Initialize the p2p server. This creates the node key and
          // discovery databases.
          n.serverConfig = n.config.P2P
          n.serverConfig.PrivateKey = n.config.NodeKey()
          n.serverConfig.Name = n.config.NodeName()
          n.serverConfig.Logger = n.log
          if n.serverConfig.StaticNodes == nil {
            n.serverConfig.StaticNodes = n.config.StaticNodes()
          }
          if n.serverConfig.TrustedNodes == nil {
            n.serverConfig.TrustedNodes = n.config.TrustedNodes()
          }
          if n.serverConfig.NodeDatabase == "" {
            n.serverConfig.NodeDatabase = n.config.NodeDB()
          }
          running := &p2p.Server{Config: n.serverConfig}
          n.log.Info("Starting peer-to-peer node", "instance", n.serverConfig.Name)

          // Otherwise copy and specialize the P2P configuration
          services := make(map[reflect.Type]Service)
          for _, constructor := range n.serviceFuncs {
            // Create a new context for the particular service
            ctx := &ServiceContext{
              config:         n.config,
              services:       make(map[reflect.Type]Service),
              EventMux:       n.eventmux,
              AccountManager: n.accman,
            }
            for kind, s := range services { // copy needed for threaded access
              ctx.services[kind] = s
            }
            // Construct and save the service
            service, err := constructor(ctx)
            if err != nil {
              return err
            }
            kind := reflect.TypeOf(service)
            if _, exists := services[kind]; exists {
              return &DuplicateServiceError{Kind: kind}
            }
            services[kind] = service
          }
          // Gather the protocols and start the freshly assembled P2P server
          for _, service := range services {
            running.Protocols = append(running.Protocols, service.Protocols()...)
          }
          if err := running.Start(); err != nil {
            return convertFileLockError(err)
          }
          // Start each of the services
          started := []reflect.Type{}
          for kind, service := range services {
            // Start the next service, stopping all previous upon failure
            if err := service.Start(running); err != nil {
              for _, kind := range started {
                services[kind].Stop()
              }
              running.Stop()

              return err
            }
            // Mark the service started for potential cleanup
            started = append(started, kind)
          }
          // Lastly start the configured RPC interfaces
          if err := n.startRPC(services); err != nil {
            for _, service := range services {
              service.Stop()
            }
            running.Stop()
            return err
          }
          // Finish initializing the startup
          n.services = services
          n.server = running
          n.stop = make(chan struct{})

          return nil
        }

startRPC方法  收集Node里面所有service的 APIs。然后分别启动了InProc IPC Http Ws这些RPC endpoint，并把收集的APIs传给这些RPC endpoint。如果任何一个RPC启动失败，结束所有RPC endpoint，并返回err。我们先看看比较常用的HTTP RPC的实现。

        func (n *Node) startRPC(services map[reflect.Type]Service) error {
          // Gather all the possible APIs to surface
          apis := n.apis()
          for _, service := range services {
            apis = append(apis, service.APIs()...)
          }
          // Start the various API endpoints, terminating all in case of errors
          if err := n.startInProc(apis); err != nil {
            return err
          }
          if err := n.startIPC(apis); err != nil {
            n.stopInProc()
            return err
          }
          if err := n.startHTTP(n.httpEndpoint, apis, n.config.HTTPModules, n.config.HTTPCors, n.config.HTTPVirtualHosts); err != nil {
            n.stopIPC()
            n.stopInProc()
            return err
          }
          if err := n.startWS(n.wsEndpoint, apis, n.config.WSModules, n.config.WSOrigins, n.config.WSExposeAll); err != nil {
            n.stopHTTP()
            n.stopIPC()
            n.stopInProc()
            return err
          }
          // All API endpoints started successfully
          n.rpcAPIs = apis
          return nil
        }

### 接下来咱们InProc IPC Http Ws这些RPC一次讲解

#### 5.1 Http RPC server源码简析

startHTTP 初始化和启动HTTP endpoint.

        func (n *Node) startHTTP(endpoint string, apis []rpc.API, modules []string, cors []string, vhosts []string) error {
          // Short circuit if the HTTP endpoint isn't being exposed
          if endpoint == "" {
            return nil
          }
          listener, handler, err := rpc.StartHTTPEndpoint(endpoint, apis, modules, cors, vhosts)
          if err != nil {
            return err
          }
          n.log.Info("HTTP endpoint opened", "url", fmt.Sprintf("http://%s", endpoint), "cors", strings.Join(cors, ","), "vhosts", strings.Join(vhosts, ","))
          // All listeners booted successfully
          n.httpEndpoint = endpoint
          n.httpListener = listener
          n.httpHandler = handler

          return nil
        }

API的数据结构

        type API struct {
          Namespace string      // namespace under which the rpc methods of Service are exposed
          Version   string      // api version for DApp's
          Service   interface{} // receiver instance which holds the methods
          Public    bool        // indication if the methods must be considered safe for public use
        }

StartHTTPEndpoint 启动HTTP RPC endpoint,用cors/vhosts/modules来配置

        func StartHTTPEndpoint(endpoint string, apis []API, modules []string, cors []string, vhosts []string) (net.Listener, *Server, error) {
          // Generate the whitelist based on the allowed modules
          whitelist := make(map[string]bool)
          for _, module := range modules {
            whitelist[module] = true
          }
          // Register all the APIs exposed by the services
          handler := NewServer()
          for _, api := range apis {
            if whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
              if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
                return nil, nil, err
              }
              log.Debug("HTTP registered", "namespace", api.Namespace)
            }
          }
          // All APIs registered, start the HTTP listener
          var (
            listener net.Listener
            err      error
          )
          if listener, err = net.Listen("tcp", endpoint); err != nil {
            return nil, nil, err
          }
          go NewHTTPServer(cors, vhosts, handler).Serve(listener)
          return listener, handler, err
        }

将api的namespace和service传入RegisterName();RegisterName将为给定名称下的给定rcvr类型创建一个服务。 如果给定的rcvr上没有方法匹配条件是RPC方法或订订阅，则返回错误。 否则，会创建一个新服务并将其添加到此服务器实例所服务的服务集合中

        func (s *Server) RegisterName(name string, rcvr interface{}) error {
          if s.services == nil {
            s.services = make(serviceRegistry)
          }

          svc := new(service)
          svc.typ = reflect.TypeOf(rcvr)
          rcvrVal := reflect.ValueOf(rcvr)

          if name == "" {
            return fmt.Errorf("no service name for type %s", svc.typ.String())
          }
          if !isExported(reflect.Indirect(rcvrVal).Type().Name()) {
            return fmt.Errorf("%s is not exported", reflect.Indirect(rcvrVal).Type().Name())
          }

          methods, subscriptions := suitableCallbacks(rcvrVal, svc.typ)

          // already a previous service register under given sname, merge methods/subscriptions
          if regsvc, present := s.services[name]; present {
            if len(methods) == 0 && len(subscriptions) == 0 {
              return fmt.Errorf("Service %T doesn't have any suitable methods/subscriptions to expose", rcvr)
            }
            for _, m := range methods {
              regsvc.callbacks[formatName(m.method.Name)] = m
            }
            for _, s := range subscriptions {
              regsvc.subscriptions[formatName(s.method.Name)] = s
            }
            return nil
          }

          svc.name = name
          svc.callbacks, svc.subscriptions = methods, subscriptions

          if len(svc.callbacks) == 0 && len(svc.subscriptions) == 0 {
            return fmt.Errorf("Service %T doesn't have any suitable methods/subscriptions to expose", rcvr)
          }

          s.services[svc.name] = svc
          return nil
        }

NewServer将创建一个没有注册句柄的新的服务实例 

        func NewServer() *Server {
          server := &Server{
            services: make(serviceRegistry),
            codecs:   set.New(),
            run:      1,
          }

          // register a default service which will provide meta information about the RPC service such as the services and
          // methods it offers.
          rpcService := &RPCService{server}
          server.RegisterName(MetadataApi, rpcService)

          return server
        }
        
在StartHTTPEndpoint中有一个NewHTTPServer方法

        func NewHTTPServer(cors []string, vhosts []string, srv *Server) *http.Server {
          // Wrap the CORS-handler within a host-handler
          handler := newCorsHandler(srv, cors)
          handler = newVHostHandler(vhosts, handler)
          return &http.Server{Handler: handler}
        }
        
实现了http.server的 ServeHTTP(w http.ResponseWriter, r *http.Request)方法。先过滤掉非法的请求，对接收到的请求body体，进行JSONCodec封装。
然后交由 srv.ServeSingleRequest(codec, OptionMethodInvocation)处理。接着调用 s.serveRequest(codec, true, options)singleShot参数是控制请求时同步还是异步。如果singleShot为true，那么请求的处理是同步的，需要等待处理结果之后才能退出。 singleShot为false，把处理请求的方法交由goroutine异步处理。Http RPC的处理是使用同步方式。
        
        func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        // Permit dumb empty requests for remote health-checks (AWS)
        if r.Method == http.MethodGet && r.ContentLength == 0 && r.URL.RawQuery == "" {
          return
        }
        if code, err := validateRequest(r); err != nil {
          http.Error(w, err.Error(), code)
          return
        }
        // All checks passed, create a codec that reads direct from the request body
        // untilEOF and writes the response to w and order the server to process a
        // single request.
        ctx := context.Background()
        ctx = context.WithValue(ctx, "remote", r.RemoteAddr)
        ctx = context.WithValue(ctx, "scheme", r.Proto)
        ctx = context.WithValue(ctx, "local", r.Host)

        body := io.LimitReader(r.Body, maxRequestContentLength)
        codec := NewJSONCodec(&httpReadWriteNopCloser{body, w})
        defer codec.Close()

        w.Header().Set("content-type", contentType)
        srv.ServeSingleRequest(codec, OptionMethodInvocation, ctx)
      }

ServeSingleRequest读取并处理来自给定编解码器的单个RPC请求。 除非发生不可恢复的错误，否则它不会关闭编解码器。 请注意，此方法将在处理完单个请求后返回！

        func (s *Server) ServeSingleRequest(codec ServerCodec, options CodecOption, ctx context.Context) {
          s.serveRequest(codec, true, options, ctx)
        }

serveRequest将从编解码器读取请求，调用RPC回调和将响应写入给定的编解码器。

如果singleShot为true，它将处理一个请求，否则它将处理请求，直到编解码器在读取请求时返回错误（在大多数情况下）一个EOF）。 它在singleShot为false时并行执行请求。

        func (s *Server) serveRequest(codec ServerCodec, singleShot bool, options CodecOption, ctx context.Context) error {
          var pend sync.WaitGroup

          defer func() {
            if err := recover(); err != nil {
              const size = 64 << 10
              buf := make([]byte, size)
              buf = buf[:runtime.Stack(buf, false)]
              log.Error(string(buf))
            }
            s.codecsMu.Lock()
            s.codecs.Remove(codec)
            s.codecsMu.Unlock()
          }()

          //	ctx, cancel := context.WithCancel(context.Background())
          ctx, cancel := context.WithCancel(ctx)
          defer cancel()

          // if the codec supports notification include a notifier that callbacks can use
          // to send notification to clients. It is thight to the codec/connection. If the
          // connection is closed the notifier will stop and cancels all active subscriptions.
          if options&OptionSubscriptions == OptionSubscriptions {
            ctx = context.WithValue(ctx, notifierKey{}, newNotifier(codec))
          }
          s.codecsMu.Lock()
          if atomic.LoadInt32(&s.run) != 1 { // server stopped
            s.codecsMu.Unlock()
            return &shutdownError{}
          }
          s.codecs.Add(codec)
          s.codecsMu.Unlock()

          // test if the server is ordered to stop
          for atomic.LoadInt32(&s.run) == 1 {
            reqs, batch, err := s.readRequest(codec)
            if err != nil {
              // If a parsing error occurred, send an error
              if err.Error() != "EOF" {
                log.Debug(fmt.Sprintf("read error %v\n", err))
                codec.Write(codec.CreateErrorResponse(nil, err))
              }
              // Error or end of stream, wait for requests and tear down
              pend.Wait()
              return nil
            }

            // check if server is ordered to shutdown and return an error
            // telling the client that his request failed.
            if atomic.LoadInt32(&s.run) != 1 {
              err = &shutdownError{}
              if batch {
                resps := make([]interface{}, len(reqs))
                for i, r := range reqs {
                  resps[i] = codec.CreateErrorResponse(&r.id, err)
                }
                codec.Write(resps)
              } else {
                codec.Write(codec.CreateErrorResponse(&reqs[0].id, err))
              }
              return nil
            }
            // If a single shot request is executing, run and return immediately
            if singleShot {
              if batch {
                s.execBatch(ctx, codec, reqs)
              } else {
                s.exec(ctx, codec, reqs[0])
              }
              return nil
            }
            // For multi-shot connections, start a goroutine to serve and loop back
            pend.Add(1)

            go func(reqs []*serverRequest, batch bool) {
              defer pend.Done()
              if batch {
                s.execBatch(ctx, codec, reqs)
              } else {
                s.exec(ctx, codec, reqs[0])
              }
            }(reqs, batch)
          }
          return nil
        }

readRequest请求来自编解码器的下一个（批次）请求。 它会返回集合的请求，指示请求是否是批处理，无效请求标识符和当请求无法读取/解析时发生错误；实际上readRequest(codec) 处理请求的codec数据。

        func (s *Server) readRequest(codec ServerCodec) ([]*serverRequest, bool, Error) {
          reqs, batch, err := codec.ReadRequestHeaders()
          if err != nil {
            return nil, batch, err
          }

          requests := make([]*serverRequest, len(reqs))

          // verify requests
          for i, r := range reqs {
            var ok bool
            var svc *service

            if r.err != nil {
              requests[i] = &serverRequest{id: r.id, err: r.err}
              continue
            }

            if r.isPubSub && strings.HasSuffix(r.method, unsubscribeMethodSuffix) {
              requests[i] = &serverRequest{id: r.id, isUnsubscribe: true}
              argTypes := []reflect.Type{reflect.TypeOf("")} // expect subscription id as first arg
              if args, err := codec.ParseRequestArguments(argTypes, r.params); err == nil {
                requests[i].args = args
              } else {
                requests[i].err = &invalidParamsError{err.Error()}
              }
              continue
            }

            if svc, ok = s.services[r.service]; !ok { // rpc method isn't available
              requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
              continue
            }

            if r.isPubSub { // eth_subscribe, r.method contains the subscription method name
              if callb, ok := svc.subscriptions[r.method]; ok {
                requests[i] = &serverRequest{id: r.id, svcname: svc.name, callb: callb}
                if r.params != nil && len(callb.argTypes) > 0 {
                  argTypes := []reflect.Type{reflect.TypeOf("")}
                  argTypes = append(argTypes, callb.argTypes...)
                  if args, err := codec.ParseRequestArguments(argTypes, r.params); err == nil {
                    requests[i].args = args[1:] // first one is service.method name which isn't an actual argument
                  } else {
                    requests[i].err = &invalidParamsError{err.Error()}
                  }
                }
              } else {
                requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
              }
              continue
            }

            if callb, ok := svc.callbacks[r.method]; ok { // lookup RPC method
              requests[i] = &serverRequest{id: r.id, svcname: svc.name, callb: callb}
              if r.params != nil && len(callb.argTypes) > 0 {
                if args, err := codec.ParseRequestArguments(callb.argTypes, r.params); err == nil {
                  requests[i].args = args
                } else {
                  requests[i].err = &invalidParamsError{err.Error()}
                }
              }
              continue
            }

            requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
          }

          return requests, batch, nil
        }
     
codec.ReadRequestHeaders()解析了请求数据；ReadRequestHeaders将读取新的请求而不解析参数。 它会返回一组请求，表示这些请求是否批量处理当传入的消息不能被读取/解析时，表单或错误

        func (c *jsonCodec) ReadRequestHeaders() ([]rpcRequest, bool, Error) {
          c.decMu.Lock()
          defer c.decMu.Unlock()

          var incomingMsg json.RawMessage
          if err := c.decode(&incomingMsg); err != nil {
            return nil, false, &invalidRequestError{err.Error()}
          }
          if isBatch(incomingMsg) {
            return parseBatchRequest(incomingMsg)
          }
          return parseRequest(incomingMsg)
        }

如果请求的数据是一组req数组用parseBatchRequest(incomingMsg)解析，否则用 parseRequest(incomingMsg)。两者处理大同小异。

        func parseBatchRequest(incomingMsg json.RawMessage) ([]rpcRequest, bool, Error) {
          var in []jsonRequest
          if err := json.Unmarshal(incomingMsg, &in); err != nil {
            return nil, false, &invalidMessageError{err.Error()}
          }

          requests := make([]rpcRequest, len(in))
          for i, r := range in {
            if err := checkReqId(r.Id); err != nil {
              return nil, false, &invalidMessageError{err.Error()}
            }

            id := &in[i].Id

            // subscribe are special, they will always use `subscriptionMethod` as first param in the payload
            if strings.HasSuffix(r.Method, subscribeMethodSuffix) {
              requests[i] = rpcRequest{id: id, isPubSub: true}
              if len(r.Payload) > 0 {
                // first param must be subscription name
                var subscribeMethod [1]string
                if err := json.Unmarshal(r.Payload, &subscribeMethod); err != nil {
                  log.Debug(fmt.Sprintf("Unable to parse subscription method: %v\n", err))
                  return nil, false, &invalidRequestError{"Unable to parse subscription request"}
                }

                requests[i].service, requests[i].method = strings.TrimSuffix(r.Method, subscribeMethodSuffix), subscribeMethod[0]
                requests[i].params = r.Payload
                continue
              }

              return nil, true, &invalidRequestError{"Unable to parse (un)subscribe request arguments"}
            }

            if strings.HasSuffix(r.Method, unsubscribeMethodSuffix) {
              requests[i] = rpcRequest{id: id, isPubSub: true, method: r.Method, params: r.Payload}
              continue
            }

            if len(r.Payload) == 0 {
              requests[i] = rpcRequest{id: id, params: nil}
            } else {
              requests[i] = rpcRequest{id: id, params: r.Payload}
            }
            if elem := strings.Split(r.Method, serviceMethodSeparator); len(elem) == 2 {
              requests[i].service, requests[i].method = elem[0], elem[1]
            } else {
              requests[i].err = &methodNotFoundError{r.Method, ""}
            }
          }

          return requests, true, nil
        }

        func parseRequest(incomingMsg json.RawMessage) ([]rpcRequest, bool, Error) {
          var in jsonRequest
          if err := json.Unmarshal(incomingMsg, &in); err != nil {
            return nil, false, &invalidMessageError{err.Error()}
          }

          if err := checkReqId(in.Id); err != nil {
            return nil, false, &invalidMessageError{err.Error()}
          }

          // subscribe are special, they will always use `subscribeMethod` as first param in the payload
          if strings.HasSuffix(in.Method, subscribeMethodSuffix) {
            reqs := []rpcRequest{{id: &in.Id, isPubSub: true}}
            if len(in.Payload) > 0 {
              // first param must be subscription name
              var subscribeMethod [1]string
              if err := json.Unmarshal(in.Payload, &subscribeMethod); err != nil {
                log.Debug(fmt.Sprintf("Unable to parse subscription method: %v\n", err))
                return nil, false, &invalidRequestError{"Unable to parse subscription request"}
              }

              reqs[0].service, reqs[0].method = strings.TrimSuffix(in.Method, subscribeMethodSuffix), subscribeMethod[0]
              reqs[0].params = in.Payload
              return reqs, false, nil
            }
            return nil, false, &invalidRequestError{"Unable to parse subscription request"}
          }

          if strings.HasSuffix(in.Method, unsubscribeMethodSuffix) {
            return []rpcRequest{{id: &in.Id, isPubSub: true,
              method: in.Method, params: in.Payload}}, false, nil
          }

          elems := strings.Split(in.Method, serviceMethodSeparator)
          if len(elems) != 2 {
            return nil, false, &methodNotFoundError{in.Method, ""}
          }

          // regular RPC call
          if len(in.Payload) == 0 {
            return []rpcRequest{{service: elems[0], method: elems[1], id: &in.Id}}, false, nil
          }

          return []rpcRequest{{service: elems[0], method: elems[1], id: &in.Id, params: in.Payload}}, false, nil
        }

解析出service名字，方法名，id，请求参数组装成rpcRequest对象，并返回。readRequest(codec ServerCodec)方法对rpcRequest再处理加工一下，然后返回。

exec执行给定的请求并使用编解码器将结果写回

        func (s *Server) exec(ctx context.Context, codec ServerCodec, req *serverRequest) {
          var response interface{}
          var callback func()
          if req.err != nil {
            response = codec.CreateErrorResponse(&req.id, req.err)
          } else {
            response, callback = s.handle(ctx, codec, req)
          }

          if err := codec.Write(response); err != nil {
            log.Error(fmt.Sprintf("%v\n", err))
            codec.Close()
          }

          // when request was a subscribe request this allows these subscriptions to be actived
          if callback != nil {
            callback()
          }
        }

handle执行一个请求并且从回调返回应答；reply := req.callb.method.Func.Call(arguments) 执行了RPC方法并返回结果reply。
codec.CreateResponse(req.id, reply[0].Interface())是rpc.json.go对返回结果的封装。
回到exec(ctx context.Context, codec ServerCodec, req *serverRequest)方法。codec.Write(response)对返回结果json序列化。
如果请求方法是订阅执行有回调callback()

        func (s *Server) handle(ctx context.Context, codec ServerCodec, req *serverRequest) (interface{}, func()) {
          if req.err != nil {
            return codec.CreateErrorResponse(&req.id, req.err), nil
          }

          if req.isUnsubscribe { // cancel subscription, first param must be the subscription id
            if len(req.args) >= 1 && req.args[0].Kind() == reflect.String {
              notifier, supported := NotifierFromContext(ctx)
              if !supported { // interface doesn't support subscriptions (e.g. http)
                return codec.CreateErrorResponse(&req.id, &callbackError{ErrNotificationsUnsupported.Error()}), nil
              }

              subid := ID(req.args[0].String())
              if err := notifier.unsubscribe(subid); err != nil {
                return codec.CreateErrorResponse(&req.id, &callbackError{err.Error()}), nil
              }

              return codec.CreateResponse(req.id, true), nil
            }
            return codec.CreateErrorResponse(&req.id, &invalidParamsError{"Expected subscription id as first argument"}), nil
          }

          if req.callb.isSubscribe {
            subid, err := s.createSubscription(ctx, codec, req)
            if err != nil {
              return codec.CreateErrorResponse(&req.id, &callbackError{err.Error()}), nil
            }

            // active the subscription after the sub id was successfully sent to the client
            activateSub := func() {
              notifier, _ := NotifierFromContext(ctx)
              notifier.activate(subid, req.svcname)
            }

            return codec.CreateResponse(req.id, subid), activateSub
          }

          // regular RPC call, prepare arguments
          if len(req.args) != len(req.callb.argTypes) {
            rpcErr := &invalidParamsError{fmt.Sprintf("%s%s%s expects %d parameters, got %d",
              req.svcname, serviceMethodSeparator, req.callb.method.Name,
              len(req.callb.argTypes), len(req.args))}
            return codec.CreateErrorResponse(&req.id, rpcErr), nil
          }

          arguments := []reflect.Value{req.callb.rcvr}
          if req.callb.hasCtx {
            arguments = append(arguments, reflect.ValueOf(ctx))
          }
          if len(req.args) > 0 {
            arguments = append(arguments, req.args...)
          }

          // execute RPC method and return result
          reply := req.callb.method.Func.Call(arguments)
          if len(reply) == 0 {
            return codec.CreateResponse(req.id, nil), nil
          }

          if req.callb.errPos >= 0 { // test if method returned an error
            if !reply[req.callb.errPos].IsNil() {
              e := reply[req.callb.errPos].Interface().(error)
              res := codec.CreateErrorResponse(&req.id, &callbackError{e.Error()})
              return res, nil
            }
          }
          return codec.CreateResponse(req.id, reply[0].Interface()), nil
        }

往client写resp  

        func (c *jsonCodec) Write(res interface{}) error {  
            c.encMu.Lock()  
            defer c.encMu.Unlock()  


            return c.e.Encode(res)  
        }  

#### 5.2.Http RPC Client的调用过程

新建一个以太坊客户端

        func NewEthereumClient(rawurl string) (client *EthereumClient, _ error) {  
            rawClient, err := ethclient.Dial(rawurl)  
            return &EthereumClient{rawClient}, err  
        }  
        
ethclient根据url拨号

        func Dial(rawurl string) (*Client, error) {  
            c, err := rpc.Dial(rawurl)  
            if err != nil {  
                return nil, err  
            }  
            return NewClient(c), nil  
        }  

调用rpc的Dial接口

        func Dial(rawurl string) (*Client, error) {
          return DialContext(context.Background(), rawurl)
        }
              
        func DialContext(ctx context.Context, rawurl string) (*Client, error) {
          u, err := url.Parse(rawurl)
          if err != nil {
            return nil, err
          }
          switch u.Scheme {
          case "http", "https":
            return DialHTTP(rawurl)
          case "ws", "wss":
            return DialWebsocket(ctx, rawurl, "")
          case "stdio":
            return DialStdIO(ctx)
          case "":
            return DialIPC(ctx, rawurl)
          default:
            return nil, fmt.Errorf("no known transport for URL scheme %q", u.Scheme)
          }
        }

根据url的scheme判断调用拨号哪个RPC server

        func DialHTTP(endpoint string) (*Client, error) {
          return DialHTTPWithClient(endpoint, new(http.Client))
        }
        
        func DialHTTPWithClient(endpoint string, client *http.Client) (*Client, error) {
        req, err := http.NewRequest(http.MethodPost, endpoint, nil)
        if err != nil {
          return nil, err
        }
        req.Header.Set("Content-Type", contentType)
        req.Header.Set("Accept", contentType)

        initctx := context.Background()
        return newClient(initctx, func(context.Context) (net.Conn, error) {
          return &httpConn{client: client, req: req, closed: make(chan struct{})}, nil
        })
      }

