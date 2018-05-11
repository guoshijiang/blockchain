
Geth中的main函数中调用了一个Run方法，该方法属于包cli中的类App的一个成员方法，下面是Run函数的具体实现

	func (a *App) Run(arguments []string) (err error) {
		a.Setup()
	
		// handle the completion flag separately from the flagset since
		// completion could be attempted after a flag, but before its value was put
		// on the command line. this causes the flagset to interpret the completion
		// flag name as the value of the flag before it which is undesirable
		// note that we can only do this because the shell autocomplete function
		// always appends the completion flag at the end of the command
		shellComplete, arguments := checkShellCompleteFlag(a, arguments)
	
		// parse flags
		set, err := flagSet(a.Name, a.Flags)
		if err != nil {
			return err
		}
	
		set.SetOutput(ioutil.Discard)
		err = set.Parse(arguments[1:])
		nerr := normalizeFlags(a.Flags, set)
		context := NewContext(a, set, nil)
		if nerr != nil {
			fmt.Fprintln(a.Writer, nerr)
			ShowAppHelp(context)
			return nerr
		}
		context.shellComplete = shellComplete
	
		if checkCompletions(context) {
			return nil
		}
	
		if err != nil {
			if a.OnUsageError != nil {
				err := a.OnUsageError(context, err, false)
				HandleExitCoder(err)
				return err
			}
			fmt.Fprintf(a.Writer, "%s %s\n\n", "Incorrect Usage.", err.Error())
			ShowAppHelp(context)
			return err
		}
	
		if !a.HideHelp && checkHelp(context) {
			ShowAppHelp(context)
			return nil
		}
	
		if !a.HideVersion && checkVersion(context) {
			ShowVersion(context)
			return nil
		}
	
		if a.After != nil {
			defer func() {
				if afterErr := a.After(context); afterErr != nil {
					if err != nil {
						err = NewMultiError(err, afterErr)
					} else {
						err = afterErr
					}
				}
			}()
		}
	
		if a.Before != nil {
			beforeErr := a.Before(context)
			if beforeErr != nil {
				fmt.Fprintf(a.Writer, "%v\n\n", beforeErr)
				ShowAppHelp(context)
				HandleExitCoder(beforeErr)
				err = beforeErr
				return err
			}
		}
	
		args := context.Args()
		if args.Present() {
			name := args.First()
			c := a.Command(name)
			if c != nil {
				return c.Run(context)
			}
		}
	
		if a.Action == nil {
			a.Action = helpCommand.Action
		}
	
		// Run default Action
		err = HandleAction(a.Action, context)
	
		HandleExitCoder(err)
		return err
	}

a.Setup仅仅是做了些简单的处理，比如相关的Auther、Email、重新创建Command切片等等.接下来我们看看下面的这个if判断

	if args.Present() {
			name := args.First()
			c := a.Command(name)
			if c != nil {
				return c.Run(context)
			}
		}

由于我们前面在控制台输入的命令（启动命令 geth + 参数）长度不为0，因此执行

	c.Run(context)

操作，此时的命令其实就是我们的console命令。接下来我们看看Run方法，Run方法的代码如下：

	func (c Command) Run(ctx *Context) (err error) {
		if len(c.Subcommands) > 0 {
			return c.startApp(ctx)
		}
	
		if !c.HideHelp && (HelpFlag != BoolFlag{}) {
			// append help to flags
			c.Flags = append(
				c.Flags,
				HelpFlag,
			)
		}
	
		set, err := flagSet(c.Name, c.Flags)
		if err != nil {
			return err
		}
		set.SetOutput(ioutil.Discard)
	
		if c.SkipFlagParsing {
			err = set.Parse(append([]string{"--"}, ctx.Args().Tail()...))
		} else if !c.SkipArgReorder {
			firstFlagIndex := -1
			terminatorIndex := -1
			for index, arg := range ctx.Args() {
				if arg == "--" {
					terminatorIndex = index
					break
				} else if arg == "-" {
					// Do nothing. A dash alone is not really a flag.
					continue
				} else if strings.HasPrefix(arg, "-") && firstFlagIndex == -1 {
					firstFlagIndex = index
				}
			}
	
			if firstFlagIndex > -1 {
				args := ctx.Args()
				regularArgs := make([]string, len(args[1:firstFlagIndex]))
				copy(regularArgs, args[1:firstFlagIndex])
	
				var flagArgs []string
				if terminatorIndex > -1 {
					flagArgs = args[firstFlagIndex:terminatorIndex]
					regularArgs = append(regularArgs, args[terminatorIndex:]...)
				} else {
					flagArgs = args[firstFlagIndex:]
				}
	
				err = set.Parse(append(flagArgs, regularArgs...))
			} else {
				err = set.Parse(ctx.Args().Tail())
			}
		} else {
			err = set.Parse(ctx.Args().Tail())
		}
	
		nerr := normalizeFlags(c.Flags, set)
		if nerr != nil {
			fmt.Fprintln(ctx.App.Writer, nerr)
			fmt.Fprintln(ctx.App.Writer)
			ShowCommandHelp(ctx, c.Name)
			return nerr
		}
	
		context := NewContext(ctx.App, set, ctx)
		if checkCommandCompletions(context, c.Name) {
			return nil
		}
	
		if err != nil {
			if c.OnUsageError != nil {
				err := c.OnUsageError(ctx, err, false)
				HandleExitCoder(err)
				return err
			}
			fmt.Fprintln(ctx.App.Writer, "Incorrect Usage:", err.Error())
			fmt.Fprintln(ctx.App.Writer)
			ShowCommandHelp(ctx, c.Name)
			return err
		}
	
		if checkCommandHelp(context, c.Name) {
			return nil
		}
	
		if c.After != nil {
			defer func() {
				afterErr := c.After(context)
				if afterErr != nil {
					HandleExitCoder(err)
					if err != nil {
						err = NewMultiError(err, afterErr)
					} else {
						err = afterErr
					}
				}
			}()
		}
	
		if c.Before != nil {
			err = c.Before(context)
			if err != nil {
				fmt.Fprintln(ctx.App.Writer, err)
				fmt.Fprintln(ctx.App.Writer)
				ShowCommandHelp(ctx, c.Name)
				HandleExitCoder(err)
				return err
			}
		}
	
		if c.Action == nil {
			c.Action = helpSubcommand.Action
		}
	
		context.Command = c
		err = HandleAction(c.Action, context)
	
		if err != nil {
			HandleExitCoder(err)
		}
		return err
	}

该主要是设置flag、解析输入的命令行参数、创建全局的context、将当前命令保存到全局context中,接下来调用HandleAction来处理命令，HandleAction的函数实现如下：

	func HandleAction(action interface{}, context *Context) (err error) 	{
		if a, ok := action.(ActionFunc); ok {
			return a(context)
		} else if a, ok := action.(func(*Context) error); ok {
			return a(context)
		} else if a, ok := action.(func(*Context)); ok { // deprecated function signature
			a(context)
			return nil
		} else {
			return errInvalidActionType
		}
	}
	
通过该函数代码重新经过相应的Init函数中的命令初始化方式进入相应的命令执行，当然，这只是简单的分析，实际的执行过程比这锅复杂得多。
