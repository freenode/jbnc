# jbnc
## Bouncer with no authentication required written in nodejs with support for separate client buffers for playback history, an always-on connection, and SSL with stunnel.

### Purpose
Bouncers are hard to configure.  I felt that we needed an easier one in this world.  This takes requires no configuration to connect!  This was a 1-day hackathon project and will improve over time.  Extremely WIP, but it works! :-)

### Example
There is an example running at `jbnc.eyearesee.com` on SSL port 9998 (or plaintext 8888).  Point your IRC client at this and set a password like:
```
SomePasswordy89153/irc.dal.net:+6697
```
There are more fine tuned instructions below to further customize and improve your experience.

### Features
- Always on connection to IRC
- No registration or account required
- Separate buffers for clients possible
- SSL with stunnel
- Tracks if your nick is changed, updates.

### Setup / Installation
1. Clone the repo
```
git clone https://github.com/realrasengan/jbnc
```
2. Edit config
```
cp example.conf jbnc.conf
<edit> jbnc.conf
```
Values:
```
mode: gateway|bouncer
bouncerPassword: leave blank for no password
serverPort: if gateway mode, else ignored
server: if gateway mode, else eignored
bouncerPort: port for bnc,
bouncerAdmin: admin pass
```

3. Run
```
node bouncer.js &
```


#### SSL
1. On Ubuntu
```
sudo apt install stunnel
```

2. Get an SSL cert from Let's Encrypt

3. Edit /etc/stunnel/stunnel.conf
```
cert = /etc/stunnel/fullchain.pem
key  = /etc/stunnel/privkey.pem
client = no

[jbnc]
accept = 9998
connect = 8888
```

### IRC Client
You just need to set your password:
For an open bouncer
```
PasswordGoesHere/ServerGoesHere
```

For a password protected one
```
ServerPassword||PasswordGoesHere/ServerGoesHere
```

To save clientbuffers for your client
```
PasswordGoesHere/ServerGoesHere/deviceid
```

Here is an example for a desktop and mobile setup with a password protected server connecting to DALnet:
```
dragon||AJFiej2fn2345/irc.dal.net:6667/desktop
dragon||AJFiej2fn2345/irc.dal.net:6667/mobile
```

#### SSL Client
Use "+port" to do SSL.  For example:
```
dragon||Ajdfklsjfa/irc.dal.net:+6697/mobile
```

#### Whilst Connected
To get a list of commands:
```
/jbnc
```

### TODO

Push notifications

On Reconnect make sure existing connections dont see whois/names/etc.

Self messages to queue for buffers

toUpperCase for commands

### Copyright
(c) 2020 Andrew Lee <andrew@imperialfamily.com>
All Rights Reserved.

MIT LICENSED
