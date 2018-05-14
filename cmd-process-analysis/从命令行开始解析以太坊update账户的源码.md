# 从命令行开始解析以太坊update账户的源码

![account](https://github.com/guoshijiang/go-ethereum-code-analysis/blob/master/cmd-process-analysis/img/3.png)

main函数中的命令启动处代码，在main.go中的init函数中存在下面这个命令

	accountCommand

在账户更新的命令行代码，这里比较简单，没有什么需要解释的，命令的使用格式为：geth account update [options] <address>

    {
            Name:      "update",
            Usage:     "Update an existing account",
            Action:    utils.MigrateFlags(accountUpdate),
            ArgsUsage: "<address>",
            Flags: []cli.Flag{
              utils.DataDirFlag,
              utils.KeyStoreDirFlag,
              utils.LightKDFFlag,
            },
            Description: `
        geth account update <address>

    Update an existing account.

    The account is saved in the newest version in encrypted format, you are prompted
    for a passphrase to unlock the account and another to save the updated file.

    This same command can therefore be used to migrate an account of a deprecated
    format to the newest format or change the password for an account.

    For non-interactive use the passphrase can be specified with the --password flag:

        geth account update [options] <address>

    Since only one password can be given, only format update can be performed,
    changing your password is only possible interactively.
    `,
          },


accountUpdate将帐户从以前的格式转换为当前帐户一个，也提供了改变口令的可能性,整个过程分为解锁账户，获取新的输入密码，更新账户成功


    func accountUpdate(ctx *cli.Context) error {
      if len(ctx.Args()) == 0 {
        utils.Fatalf("No accounts specified to update")
      }
      stack, _ := makeConfigNode(ctx)
      ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

      for _, addr := range ctx.Args() {
        account, oldPassword := unlockAccount(ctx, ks, addr, 0, nil)
        newPassword := getPassPhrase("Please give a new password. Do not forget this password.", true, 0, nil)
        if err := ks.Update(account, oldPassword, newPassword); err != nil {
          utils.Fatalf("Could not update the account: %v", err)
        }
      }
      return nil
    }


检索使用的帐户管理器

    func (n *Node) AccountManager() *accounts.Manager {
      return n.accman
    }

从帐户管理器中检索具有给定类型的后端

    func (am *Manager) Backends(kind reflect.Type) []Backend {
      return am.backends[kind]
    }

尝试解锁指定的账户三次，三次中如果有一次成功，那么就解锁成功，三次中一次都不能解锁账户成功，那么久解锁账户失败

	    // tries unlocking the specified account a few times.
	    func unlockAccount(ctx *cli.Context, ks *keystore.KeyStore, address string, i int, passwords []string) (accounts.Account, string) {
	      //获取账户的地址
	      account, err := utils.MakeAddress(ks, address)
	      if err != nil {
		utils.Fatalf("Could not list accounts: %v", err)
	      }

	      //尝试解锁三次
	      for trials := 0; trials < 3; trials++ {
		prompt := fmt.Sprintf("Unlocking account %s | Attempt %d/%d", address, trials+1, 3)
		password := getPassPhrase(prompt, false, i, passwords)
		err = ks.Unlock(account, password)
		if err == nil {
		  log.Info("Unlocked account", "address", account.Address.Hex())
		  return account, password
		}
		if err, ok := err.(*keystore.AmbiguousAddrError); ok {
		  log.Info("Unlocked account", "address", account.Address.Hex())
		  return ambiguousAddrRecovery(ks, err, password), password
		}
		if err != keystore.ErrDecrypt {
		  // No need to prompt again if the error is not decryption-related.
		  break
		}
	      }
	      // All trials expended to unlock account, bail out
	      // 尝试解锁账户失败
	      utils.Fatalf("Failed to unlock account %s (%v)", address, err)

	      return accounts.Account{}, ""
	    }
	    
	    
MakeAddress将直接指定的帐户转换为十六进制编码的字符串或密钥存储中的一个关键索引，用于内部帐户表示

	    func MakeAddress(ks *keystore.KeyStore, account string) (accounts.Account, error) {
	      // If the specified account is a valid address, return it
	      // 如果指定的账户是一个无效地址，直接返回
	      if common.IsHexAddress(account) {
		return accounts.Account{Address: common.HexToAddress(account)}, nil
	      }
	      // Otherwise try to interpret the account as a keystore index
	      // 否则，请尝试将该帐户解析为密钥库索引
	      index, err := strconv.Atoi(account)
	      if err != nil || index < 0 {
		return accounts.Account{}, fmt.Errorf("invalid account address or index %q", account)
	      }
	      log.Warn("-------------------------------------------------------------------")
	      log.Warn("Referring to accounts by order in the keystore folder is dangerous!")
	      log.Warn("This functionality is deprecated and will be removed in the future!")
	      log.Warn("Please use explicit addresses! (can search via `geth account list`)")
	      log.Warn("-------------------------------------------------------------------")

	      accs := ks.Accounts()
	      if len(accs) <= index {
		return accounts.Account{}, fmt.Errorf("index %d higher than number of accounts %d", index, len(accs))
	      }
	      return accs[index], nil
	    }


返回所有当前目录中的key文件

	    func (ks *KeyStore) Accounts() []accounts.Account {
	      return ks.cache.accounts()
	    }

	    func (ac *accountCache) accounts() []accounts.Account {
	      ac.maybeReload()
	      ac.mu.Lock()
	      defer ac.mu.Unlock()
	      cpy := make([]accounts.Account, len(ac.all))
	      copy(cpy, ac.all)
	      return cpy
	    }


检索与帐户关联的密码，或者从预先加载的密码短语列表中获取密码，或者从用户交互地请求密码

	    func getPassPhrase(prompt string, confirmation bool, i int, passwords []string) string {
	      // If a list of passwords was supplied, retrieve from them
	      if len(passwords) > 0 {
		if i < len(passwords) {
		  return passwords[i]
		}
		return passwords[len(passwords)-1]
	      }
	      // Otherwise prompt the user for the password
	      if prompt != "" {
		fmt.Println(prompt)
	      }

	      // 从控制台获取密码
	      password, err := console.Stdin.PromptPassword("Passphrase: ")
	      if err != nil {
		utils.Fatalf("Failed to read passphrase: %v", err)
	      }

	      // 从控制台获取确认密码
	      if confirmation {
		confirm, err := console.Stdin.PromptPassword("Repeat passphrase: ")
		if err != nil {
		  utils.Fatalf("Failed to read passphrase confirmation: %v", err)
		}
		if password != confirm {
		  utils.Fatalf("Passphrases do not match")
		}
	      }
	      return password
	    }

根据密码解锁账户

	    func (ks *KeyStore) Unlock(a accounts.Account, passphrase string) error {
	      return ks.TimedUnlock(a, passphrase, 0)
	    }

TimedUnlock使用密码解锁给定帐户。 该帐户在超时期间保持解锁状态。 在程序退出之前，超时值为0会解锁该帐户。 该帐户必须匹配唯一的密钥文件
如果帐户地址已解锁一段时间，则TimedUnlock扩展或缩短活动解锁超时。如果地址先前无限期解锁，则超时不会更改

	    func (ks *KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	      a, key, err := ks.getDecryptedKey(a, passphrase)
	      if err != nil {
		return err
	      }

	      ks.mu.Lock()
	      defer ks.mu.Unlock()
	      u, found := ks.unlocked[a.Address]
	      if found {
		if u.abort == nil {
		  // The address was unlocked indefinitely, so unlocking
		  // it with a timeout would be confusing.
		  zeroKey(key.PrivateKey)
		  return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	      }
	      if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go ks.expire(a.Address, u, timeout)
	      } else {
		u = &unlocked{Key: key}
	      }
	      ks.unlocked[a.Address] = u
	      return nil
	    }

AmbiguousAddrError是试图解锁存在多个文件的地址

	    type AmbiguousAddrError struct {
	      Addr    common.Address
	      Matches []accounts.Account
	    }

	    func ambiguousAddrRecovery(ks *keystore.KeyStore, err *keystore.AmbiguousAddrError, auth string) accounts.Account {
	      fmt.Printf("Multiple key files exist for address %x:\n", err.Addr)
	      for _, a := range err.Matches {
		fmt.Println("  ", a.URL)
	      }
	      fmt.Println("Testing your passphrase against all of them...")
	      var match *accounts.Account
	      for _, a := range err.Matches {
		if err := ks.Unlock(a, auth); err == nil {
		  match = &a
		  break
		}
	      }
	      if match == nil {
		utils.Fatalf("None of the listed files could be unlocked.")
	      }
	      fmt.Printf("Your passphrase unlocked %s\n", match.URL)
	      fmt.Println("In order to avoid this warning, you need to remove the following duplicate key files:")
	      for _, a := range err.Matches {
		if a != *match {
		  fmt.Println("  ", a.URL)
		}
	      }
	      return *match
	    }

更新一个存在的账户

	    func (ks *KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	      a, key, err := ks.getDecryptedKey(a, passphrase)
	      if err != nil {
		return err
	      }
	      // 将新的加密key存储
	      return ks.storage.StoreKey(a.URL.Path, key, newPassphrase)
	    }

获取加密key

	    func (ks *KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	      a, err := ks.Find(a)
	      if err != nil {
		return a, nil, err
	      }
	      // 获取key
	      key, err := ks.storage.GetKey(a.Address, a.URL.Path, auth)
	      return a, key, err
	    }
