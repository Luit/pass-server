# pass-server

This is a server for the [pass-browser-chrome][] Chrome extension. This server
is a bit different from the one made by [cpoppema][]. Apart from being written
in [Go][] instead of [Node.js][], this server is written in two parts:

1. `pass-indexer` copies a [pass][] password store into a folder with the
secrets ASCII-armor encoded, and an encrypted index.

2. `pass-proxy` serves as a compatibility layer for the current version of
pass-browser-chrome to access a password store from a folder created by the
indexer, served by a regular webserver.

In the end, I'd like to see the Chrome extension changed to work with the
files created by `pass-indexer` when served by a regular webserver. This way,
just about anyone can create a server for this Chrome extension.

[pass-browser-chrome]: https://github.com/cpoppema/pass-browser-chrome/ (cpoppema/pass-browser-chrome)
[cpoppema]: https://github.com/cpoppema (cpoppema)
[Go]: https://golang.org/ (The Go Programming Language)
[Node.js]: https://nodejs.org/ (Node.js)
[pass]: https://www.passwordstore.org/ (Pass: The Standard Unix Password Manager)
