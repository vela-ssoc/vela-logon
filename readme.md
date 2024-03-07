# 登录事件
> 监控系统上的登录事件 包括:fail,success,logout

## 内置方法
- [vela.logon.fail()](#登录失败)    &emsp;登录失败事件
- [vela.logon.success()](#登录成功) &emsp;登录成功事件
- [vela.logon.logout()](#登录注销)  &emsp;登录失败事件
- [系统登录事件](#Event)

## 配置接口
- [o.history(function)](#) &emsp;获取history
- [o.pipe()](#)            &emsp;遍历事件
- [o.filter(cnd)](#)       &emsp;过滤事件
- [o.ref()](#)             &emsp;关联进程
- [o.output()](#)          &emsp;是否输出

## 登录失败
> f = vela.logon.fail() <br />
> 满足统一配置 和 方法[配置接口](#配置接口)
```lua
    local f = vela.logon.fail()
    f.pipe(print)
    f.history(print)
```
## 登录成功
> f = vela.logon.success() <br />
> 满足统一配置 和 方法[配置接口](#配置接口)
```lua
    local f = vela.logon.success()
    f.pipe(print)
    f.history(print)
```

## 登录注销
> f = vela.logon.logout() <br />
> 满足统一配置 和 方法[配置接口](#配置接口)
```lua
    local f = vela.logon.logout()
    f.pipe(print)
    f.history(print)
```


## Event
> 封装登录事件对象

- user
- addr
- time
- host
- pid
- class
- process
- type
- [report()](#) &emsp;上报事件

```lua
    local f = vela.logon.fail()
    f.pipe(function(ev)
        ev.exdata("aaa")
        ev.exdata("bbb")
        print(ev.user , " " , ev.addr)
        ev.report()
    end)

```