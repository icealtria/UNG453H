# UNG453H (Go)

获取 UNG453H 超级管理员与 PPPoE 账号密码。

## 运行

```bash
go run ./cmd/cmcc-getpwd
# 或
go run ./cmd/cmcc-getpwd -p 你的光猫密码
```

## 构建

```bash
go build -o cmcc-getpwd ./cmd/cmcc-getpwd
```

## 使用说明

1. 确保电脑已连接到光猫的 WiFi 或网线；
2. 运行程序，输入光猫背面的普通用户密码（`user` 账号）；
3. 程序会开启 telnet、登录光猫，并读取配置文件，输出超级管理员账号密码和 PPPoE 账号密码。

## 免责声明

本工具仅供学习和研究使用，请勿用于非法用途。使用本工具所造成的任何问题由使用者自行承担。
