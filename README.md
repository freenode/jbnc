# jbnc
## IRC Bouncer/IRC Gateway with no authentication required written in nodejs with support for separate client buffers for playback history, an always-on connection, and SSL in and out.

## This is the missing link for IRC.

### Purpose
Bouncers are hard to configure.  I felt that we needed an easier one in this world.  This requires nearly no configuration to connect!  Just set a password!
Join #jbnc on freenode to learn more!

*Currently usable, but in beta test.  Please report bugs by creating an issue on github.  I'm using it as my daily driver.*

### Features
- Always on connection to IRC
- No registration or account required
- Separate buffers for clients
- SSL with stunnel
- Works with any RFC 1459 Compatible Client
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
webircPassword: if its there, it will try webirc authentication
bouncerPort: port for bnc,
bouncerAdmin: admin pass
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
Sometimes stunnel crashes, so in order to keep things running 24/7/365, there's a great app called [immortal](https://immortal.run/).

The immortaldir files are located in this repo (stunnel.yml and jbnc.yml).

Note: To use immortal on ubuntu, after following the steps on the page, please be sure to `systemctl enable immortaldir` as well as start.


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
4. Run!

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


### TODO

Beta Testing

### Copyright
(c) 2020 Andrew Lee <andrew@imperialfamily.com>
All Rights Reserved.

MIT LICENSED
