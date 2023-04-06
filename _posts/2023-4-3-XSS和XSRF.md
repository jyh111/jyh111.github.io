---
layout: post
title: XSS与XSRF
subtitle: 攻击原理简析
author: Jimmy
categories: 前端学习
tags: XSS XSRF
sidebar: []
---

# XSS

## 参考

[详解XSS攻击与CSRF攻击](https://blog.csdn.net/weixin_43514149/article/details/107545899)
[一文读懂XSS、CSRF、SSRF、XXE漏洞原理、应用、防御](http://www.360doc.com/showweb/0/0/1075061881.aspx)

XSS中文名称就是跨站脚本攻击。XSS的重点不在于跨站点而在于脚本的执行，那么XSS的原理是：恶意攻击者在web页面中会插入一些恶意的script代码。当用户浏览该页面的时候，那么嵌入到web页面中的script代码会执行，因此会达到恶意攻击用户的目的。

XSS是服务器对用户输入的数据没有进行足够的过滤，导致客户端浏览器在渲染服务器返回的html页面时，出现了预期值之外的脚本语句被执行。


## 反射型

因此反射型xss的攻击步骤如下：

1. 攻击者在url后面的参数中加入恶意攻击代码
2. 当用户打开恶意代码的url的时候，网站服务器端将恶意代码从服务器端提取，拼接在html中并返回给浏览器端
3. 用户浏览器接收到响应后执行解析，其中恶意代码就被执行
4. 攻击者将通过恶意代码来窃取到用户数据并发送到攻击者网站，攻击者会获取到比如cookie等信息，然后使用信息来冒充用户的行为

常见的反射型xss攻击：恶意链接


## 存储型XSS

存储型XSS主要是将恶意代码上传或存储到服务器中，下次只要受害者浏览包含此恶意代码的页面就会执行恶意代码‘，简而言之，提交的代码会存储在服务器端,不用再提交XSS代码。

存储型XSS攻击步骤如下：

1. 攻击者将恶意代码提交到目标网站数据库中
2. 用户打开目标网站的时候，网站服务器将恶意代码从数据库中提取出来，然后拼接到html中返回给浏览器
3. 用户浏览器接收响应后解析执行，那么其中的恶意代码也会被执行
4. 那么恶意代码执行之后，就能获取到用户数据，比如上面的cookie等信息


# HTTP Cookie
XSRF利用Cookie，先学习Http cookie机制
## 参考
[http cookie](https://www.jianshu.com/p/fe0a4b5943e3)

## 什么是Cookie
HTTP cookie（也称为web cookie、internet cookie、浏览器 cookie 或简称 cookie）是在用户浏览网站时由服务器端创建并由用户的浏览器放置在用户计算机或其他设备上的小块数据。 cookie 放置在用于访问网站的设备上，并且在会话期间可能会在用户的设备上放置多个 cookie。

特点：
- 由服务器端创建
- 由浏览器存储在电脑硬盘或其他设备上
- 数据很小，但可以针对一个网站存储多个cookie

## cookie可以做什么
1、 存储登录信息 2、存储设置信息 3、 存储部分用户数据（如购物车）
大多数的浏览器都对cookie做了一些限制，比如：

最多一个站点300个cookie
每个cookie只有4096 bytes
根据每个domain存储，不允许跨域，即a站点的cookie不能被b站点共享，反之亦然。
专业描述这些特点分别是：

会化管理 ：每次记录你的登录信息其实就是一种回话管理。
私人订制：搜索网站可以针对你个人的搜索存储你的偏好设置，本质上就是私人定制。
追踪：有些网站还会分析你本地的cookie文件，从而确定偏好甚至是更敏感的信息。

## cookie的工作机制
浏览器向 www.example.org 网站的主页发送其第一个 HTTP 请求
```
GET /index.html HTTP/1.1
Host: www.example.org
...
```

服务器响应如下
```
HTTP/1.0 200 OK
Content-type: text/html
Set-Cookie: theme=light
Set-Cookie: sessionToken=abc123; Expires=Wed, 09 Jun 2021 10:18:14 GMT
...
```
服务器的 HTTP 响应包含网站主页的内容。 但它也指示浏览器设置两个 cookie。 第一个“主题”被认为是会话 cookie，因为它没有 Expires 或 Max-Age 属性。 会话 cookie 旨在在浏览器关闭时由浏览器删除。 第二个“sessionToken”被认为是持久性 cookie，因为它包含一个 Expires 属性，该属性指示浏览器在特定日期和时间删除 cookie。

接下来当浏览器再访问该host的页面时，浏览器会自动携带Cookie
```
GET /spec.html HTTP/1.1
Host: www.example.org
Cookie: theme=light; sessionToken=abc123
…
```
## cookie 的权限控制
HTTP提供了两个属性来对cookies的权限进行控制，分别是Secure和HttpOnly。

如果cookies中带有Secure属性，那么cookies只会在使用HTTPS协议的时候发送给服务器。如果使用的是HTTP协议，则不会发送cookies信息。

并且，如果是在http的情况下，server端是不允许给cookie设置Secure属性的。

但是设置了Secure属性并不意味着cookies就是安全的，因为可以从其他的手段拿到浏览器端的cookies。

还有一个属性是HttpOnly，如果cookies设置了HttpOnly，那么cookies是不允许被JavaScript访问的，通过设置HttpOnly，我们可以提升客户端数据的安全性：

```
Set-Cookie: id=abcdef; Expires=Thu, 21 May 2021 08:00:00 GMT; Secure; HttpOnly
```


# XSRF
[前端安全之xss与xsrf](https://blog.csdn.net/qq_41801117/article/details/115267308)
xsrf 的全称是“跨站请求伪造”，它利用的是服务器对客户端浏览器的信任，从而伪造用户向服务器发送请求，从而欺骗服务器达到一些目的。

CSRF(跨站请求伪造)是服务器端没有对用户提交的数据进行随机值校验，且对http请求包内的refer字段校验不严，导致攻击者可以利用用户的Cookie信息伪造用户请求发送至服务器。 

用户登录，网站A核查身份是否正确，正确就下发cookie
cookie会保存在用户的浏览器中，这就完车了一次身份认证的过程
接下来呢，用户又访问了一个网站B，网站B在给用户返回页面的时候，会携带一个引诱性的点击，这个点击往往是一个链接，这个链接一般就是网站A的API接口。当用户点击了这个链接后，这个点击就访问了A网站，当我们访问A网站的时候咱们都知道浏览器会自动上传cookie，这个时候网站A觉得这个cookie拿到了，对身份进行了重新确认，身份没有问题就相当于执行了这个接口的动作。

CRSF造成攻击的两个前提，第一：网站中某个接口存在漏洞；第二：用户在这个网站一定登陆过，这是实现CSRF攻击的两个基本前提



