# CSSWAF

> Inspired by [anubis](https://github.com/TecharoHQ/anubis)

## What is CSSWAF?

CSSWAF places random hidden `empty.gif` files in CSS animation progress, allowing the browser to load these images one by one.
The backend measures the loading order. If the loading order is correct, it is identified as a browser; otherwise, it is identified as a bot.

## HoneyPot

CSSWAF places some honeypot `empty.gif` files in HTML `<img>` tags but instructs the browser not to load them.
If someone loads the honeypot GIFs, 🙅.