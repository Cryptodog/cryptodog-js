# cryptodog-js (Work in progress)

This package aims to provide a modular, event-based, and readable implementation of core Cryptodog messaging, cryptography and network functions.

It comes with the same caveats of the mainline Cryptodog, although this package's codebase has never been audited.

In lieu of [StropheJS](https://github.com/strophe/strophejs) it uses [stanza.io](https://github.com/legastero/stanza.io), the XMPP library used by [Nadim Kobeissi's 2017 rewrite of Cryptocat.](https://crypto.cat/)

# Binary Extensions

This package provides a new metadata format that adds extensible functionality to Cryptodog which is transferred through OTR and Multiparty. 

### Features (to be implemented)

- Message caching (resilience to bad networking conditions) ❌
- Group messaging ✔
- Private messaging ❌
- VoIP signaling ❌