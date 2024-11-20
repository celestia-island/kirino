<img src="splash.png" alt="kirino" />

![Crates.io License](https://img.shields.io/crates/l/kirino)
[![Crates.io Version](https://img.shields.io/crates/v/kirino)](https://docs.rs/kirino)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/celestia-island/kirino/test.yml)

## Introduction

A customizable, zero-trust authentication framework.

The name `kirino` comes from the character [Kirino](https://bluearchive.wiki/wiki/kirino) in the game [Blue Archive](https://bluearchive.jp/).

> Still in development, the API may change in the future.

## TODOs

- [ ] 编写一套围绕“身份”和“凭证”生成“凭据”的验证框架
  - [ ] 为“身份”提供多种预设模板，包括：
    - [ ] 匿名帐户
    - [ ] 一般用户，默认情况下只有最小权限，如有需要权限时只能通过临时提权操作，通过关联服务账户来获得限时权限
    - [ ] 关联服务账户，用于“借用”权限给拥有提权权限的最小默认权限账户，一般而言这种用户的名字本身就对应具体权限
    - [ ] 临时账户，相比较于一般账户，临时账户只能在一定时间内拥有一定权限
  - [ ] 为“凭证”提供多种预设模板，包括：
    - [ ] 基于密码的凭证
      - [ ] 一次性密码
      - [ ] 常驻密码
      - [ ] 应用程序密码，即一个账户下通过设定多个密码来分别用于授权不同的内容
    - [ ] 基于公私钥的凭证，可通过 SSH 密钥、TLS 证书等方式验证
    - [ ] 单点登录凭证，可通过 OAuth 等方式验证
    - [ ] 动态验证码凭证，可通过 OTP、邮箱验证码、手机验证码等方式验证
    - [ ] 机器人识别凭证，可通过 reCAPTCHA 等方式验证
    - [ ] 生物识别凭证，可通过指纹、声纹、面部识别等方式验证
  - [ ] 为“凭据”提供多种预设模板，包括：
    - [ ] 一次性凭据，用于一次性操作
    - [ ] 限时凭据，用于限时操作
    - [ ] 永久凭据，用于永久操作，仅适用于关联服务账户的保持权限
  - [ ] 设计一批内置的只用于角色管理的关联服务账户，用于提供最基本的注册、重置凭证、用户管理等服务
- [ ] 为凭据支持 JWT 标准
  - [ ] 支持手动刷新，以注销旧凭据
  - [ ] 支持过期，包括检查生效起始时间与过期时间
  - [ ] 支持自动刷新凭据验证码，以规避重放攻击问题
- [ ] 为“身份”、“凭证”与“凭据”缓存准备可供数据库进行存储的接口
  - [ ] 支持 SQL 数据库，每个身份一行，可以包含若干份凭证与凭据缓存
  - [ ] 支持 NoSQL 数据库，身份与凭证作为二元组存储，凭据缓存能够反向查询到对应身份与凭证
- [ ] 单点登录支持
- [ ] 本地验证码服务支持
