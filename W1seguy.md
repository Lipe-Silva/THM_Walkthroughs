# W1seguy 🤖
A w1se guy 0nce said, the answer is usually as plain as day.
## introduction
This Capture the flag is a short but fun challenge about braking cryptography. So start the machine and lets dive in. 

you can find this CTF at https://tryhackme.com/r/room/w1seguy
![]()
### port scanning
first things first we should try to connect to the server on port 1337 just to get an understanding of what we are up against. We can connect to the server using the netcat tool using the following command: `nc <ip_address> 1337`

if you connect successfully to the server you are greeted with the following prompt:
```
This XOR encoded text has flag 1: 183f1f39007d163e2c04090f26030438433129130d19207111203b2b2a253e032b72053e0f1d300d
What is the encryption key?
```
Great! From this we learned that flag 1 is encoded in this text:
`183f1f39007d163e2c04090f26030438433129130d19207111203b2b2a253e032b72053e0f1d300d` 

Its encoded using **XOR Encoding** and we can decode the flag if we have the decryption key. But for now we have no idea what's the encryption key, so let's analyse the code given to us to see if we can find anything useful to break the cipher.
### code analysis

Now lets take a look at the code, download it and open it up with any code editor of your preference. Also if you have any trouble with code analysis you can put it into chatgpt and ask it to explain the code. But, basically the code is a demo of the server on port 1337 the only diference being the fake flag.

<details>
<summary>full code</summary>
  
This code is a demo of the server located on port 1337

```python

import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```
</details>

there are two note worthy parts of the code that can help us break the cipher, first
```
    hex_encoded = xored.encode().hex()
    return hex_encoded
 ```
from this snipet of code we can conclude that **the flag is first XOR Encoded then Hex Encoded** 

and last and most importantly,
```
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
key = str(res)
```
from this we conclude that **the encryption key is alphanumerical and only 5 digits in length**

with these two clues in mind we can try to find the encyption key and break the cipher. 
![]()
## first flag
A common approach to cipher cracking is to look for repeating letters and patterns. As you might have noticed every flag on Tryhackme starts with "THM{" we can use this information to partialiy crack the key.

We can use a tool like https://gchq.github.io/CyberChef/ to achive this

Basically if we have a piece of the input text and the corresponding piece of the cipher text we can produce a piece of the encryption key

Since THM{ are the first characters in the original text they must be the first 4 bits in the cipher text and from that we can get the first four letters in the encryption key 
![]()
## second flag

![]()
