# jbnc
## IRC Bouncer/IRC Gateway with no authentication required written in nodejs with support for separate client buffers for playback history, an always-on connection, and SSL in and out.

## This is the missing link for IRC.

### Purpose
Bouncers are hard to configure.  I felt that we needed an easier one in this world.  This requires nearly no configuration to connect!  Just set a password!
Join #jbnc on freenode to learn more!

While I'm using this as my daily driver, you may run into some bugs until the beta test period is over.  That said, there are many users who are stably using it today!

### Features
- Always on connection to IRC
- No registration or account required
- Separate buffers for clients
- SSL
- Works with any RFC 1459 Compatible Client
- Password can be changed in the config and a HUP will reload the passwords.
- ***Gateway Mode for IRC Servers and Networks (See Below)***

### Compatibility
Works on:
- Freenode
- Rizon
- DALnet
- OFTC
- EFnet
- Any RFC1459 Compliant Network/Server

### Setup / Installation
1. Clone the repo
```
git clone https://github.com/realrasengan/jbnc
```
2. Edit config (there are different example.confs for different use cases)
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
webircPassword: if its there, it will try webirc authentication
webircHashIp: true or false if you want to just hide their ip but provide a hash
webircProxy: true or false if you want to pass their real ip (only matters with stunnel)
ingresswebircPassword: a password for webirc clients to use when connecting to jbnc
bouncerIp: ip you want to bind to or leave null
bouncerPort: port for bnc (do "+6697" if you want SSL (wrap in "" and put +)),
bouncerAdmin: admin pass
bouncerShack: ping ack timeout
bouncerDefaultOpmode: auto op/voice/hop mode default (can be turned on per client using /jbnc)
bouncerTimeout: how long until after no clients connected will the user stay connected
bufferMaxSize: maximum # of bytes a client buffer can hold before its terminated or 0 for unlimited
```

3. Run
To use the default jbnc.conf in the same folder:
```
node bouncer.js &
```

To use another config file:
```
node bouncer.js somefile.conf &
```

#### Keep it running forever (no downtime)
To keep things running 24/7/365, there's a great app called [immortal](https://immortal.run/).

The immortaldir files are located in this repo (jbnc.yml).

Note: To use immortal on ubuntu, after following the steps on the page, please be sure to `systemctl enable immortaldir` as well as start.

### IRC Client
You just need to set your password in your jbnc config and then setup your IRC client:
Just put this in your password:
```
YourServerPassword||ConnectionPasswordGoesHere/ServerGoesHere
```
To save clientbuffers for your client
```
YourServerPassword||ConnectionPasswordGoesHere/ServerGoesHere/deviceid
```

Here is an example for a desktop and mobile setup with a password protected server (password: dragon) connecting to DALnet:
```
dragon||AJFiej2fn2345/irc.dal.net:6667/desktop
dragon||AJFiej2fn2345/irc.dal.net:6667/mobile
```

Here is an example for a desktop connecting to an irc server that is password protected and a bnc that is password protected:
```
dragon||AJFiej2fn2345/irc.dal.net:6667||somepassword/desktop
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

## Gateway Mode
Enable gateway mode and run on the same box as your IRCd to instantly give all your users always on connectivity and seamless synchronization across all devices.

1. Edit the config file and use gateway mode instead of bouncer.

2. Run

### Gateway Mode Setup on Client Side

If you are running jbnc on the same machine as your irc server, let's say irc.example.com, then the only difference would be that your users would need to:

1. Use a different port (8888 default for plaintext and 9998 default for SSL)

2. Enter a password in their IRC client.  They make up the password and use it to identify to their connection.
```
SomePassword/buffername
```

An example buffername could be 'desktop' and on the mobile phone could be 'mobile.'


### Copyright
(c) 2020 Andrew Lee <andrew@imperialfamily.com>
All Rights Reserved.

MIT LICENSED
