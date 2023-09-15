# DigitalGuard使用说明

## 内容清单

| 文件                 | 说明               | 备注                                       |
| -------------------- | ------------------ | ------------------------------------------ |
| DigitalGuard.exe     | 可执行文件         |                                            |
| config.yaml          | 配置文件           |                                            |
| windows-manifest.xml | 自动生成的xml文件  |                                            |
| wintun.dll           | wintun的动态库文件 | 保持和可执行文件在同意目录下，不要修改名称 |

## 启动方法

windows命令行下执行 DigitalGuard.exe install-system-daemon 会自动将可执行文件作为系统服务运行，服务名称为：DigitalGuardD

windows命令行下执行 DigitalGuard.exe uninstall-system-daemon 会将该服务停止和删除

## 配置设定

配置的设定在config.yaml文件中

```
controlUrl: https://controlplane.tailscale.com
authKey: tskey-auth-kRHXEb2CNTRL-CgdxZTYTmue6o8seXzKjueUMwkkCL4hd
dataDir: C:\Users\JIT-Unassigned\Documents\DigitalGuardState
hostSuffix: digital_guard
advertiseRoutes:
    - 10.0.0.0/8
    - 172.16.21.252/32
    - 192.168.0.0/24
```

| 配置项          | 说明                | 备注                                                         |
| --------------- | ------------------- | ------------------------------------------------------------ |
| controlUrl      | 服务端的地址        | 必须配置                                                     |
| authKey         | 验证的key           | 必须配置                                                     |
| dataDir         | state文件的保持地址 | 建议配置，因为state文件会在运行中状态更新时进行写入，在开始时会读取或者生成，需要将目录配置成可读可写 |
| hostSuffix      | 节点后缀            | 可以不配置，默认值为digital_guard                            |
| advertiseRoutes | 子网路由            | 没有默认值                                                   |

## 日志路径

C:\ProgramData\DigitalGuard\Logs

## 服务接口

port 8090

| API             | 说明                  | 备注                                                         |
| --------------- | --------------------- | ------------------------------------------------------------ |
| /getIPs         | 查询tailscale的ip地址 |                                                              |
| /getState       | 查询服务的运行状态    |                                                              |
| /login          | 登录到服务端          | 系统服务在开启后会自动登录                                   |
| /logout         | 登出                  |                                                              |
| /disconnect     | 断开连接              | 断开或者登出后再次连接需要login                              |
| /configRouteAll | 启动/禁用子网路由     | 参数 enable：-1禁用 ，其他：启动. exp: curl http://localhost:8090/configRouteAll?enable=-1 禁用子网路由 |

接口名称可以按需修改