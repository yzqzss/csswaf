# CSSWAF

> Inspired by [anubis](https://github.com/TecharoHQ/anubis)

> !WARNING! This is a very simple Proof of Concept and **should not be used in production**.

https://github.com/user-attachments/assets/3684cbed-5fc8-425d-98e9-5742407de8ae

Demo: https://csswaf-demo.othing.xyz

## What is CSSWAF?

CSSWAF places random hidden `empty.gif` files in CSS animation progress, allowing the browser to load these images one by one.
The backend measures the loading order. If the loading order is correct, it passes the request to the target server. Otherwise, 🙅.

## HoneyPot

CSSWAF places some honeypot `empty.gif` files in HTML `<img>` tags but instructs the browser not to load them. If someone loads the honeypot GIFs, 🙅.
CSSWAF also places some unvisible `<a>` tags in HTML, if someone clicks the honeypot links, 🙅.

## Usage

```shell
Usage of csswaf:
  -bind string
        address to bind to (default ":8081")
  -target string
        target to reverse proxy to (default "http://localhost:8080")
  -ttl duration
        session expiration time (default 1h0m0s)
```