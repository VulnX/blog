---
title: Deb File | The Old Systems
date: 2023-09-02 21:10:00 + 0530
categories: [writeup, steganography]
tags: [urmia]     # TAG names should always be lowercase
---

## The Challenge

> Can you believe it? people still use linux? after the emerge of Evil E computers, nobody bothered to use linux systems. anyways, we got this file from database gaurds' pc, can you help us?
> 
> Attachment : uctfdeb-0.0.1.deb

## The Solution

We are given a Debian Binary Package file, so I went straight to install it via `dpkg`.
> Never do this with a random binary from the internet
{: .prompt-danger }


```console
$ sudo dpkg -i uctfdeb-0.0.1.deb
```

and then ran `uctf`:
```console
$ uctf
curl: (7) Failed to connect to 127.0.0.1 port 7327 after 0 ms: Couldn't connect to server
```

The application was trying to connect to 127.0.0.1 on port 7327 most likely to communicate something ( my guess was : it's sending the flag ). So I opened a `netcat` receiver session in a new window and ran `uctf` again:
```console
$ nc -nvlp 7327
listening on [any] 7327 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37996
GET / HTTP/1.1
Host: 127.0.0.1:7327
User-Agent: curl/7.88.1
Accept: */*
flag: UCTF{c4n_p3n6u1n5_5urv1v3_1n_54l7_w473r}
```


## FLAG

`UCTF{c4n_p3n6u1n5_5urv1v3_1n_54l7_w473r}`

