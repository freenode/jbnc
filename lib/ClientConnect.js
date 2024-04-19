
/*global global, module, require*/
/*eslint no-undef: "error"*/

const tls = require('tls');
const net = require('net');
const dns = require('dns');
const reverse = require('util').promisify(dns.reverse);
const crypto = require("crypto");

class ClientConnect {
    constructor(socket, connection) {
        this.connection = connection;
        this._success = true;
        this._connector = net.createConnection;
        this._tempport = socket.irc.port.toString();
        this._ssl = false;
        this._options = {
            rejectUnauthorized: true
        };
        this.init(socket);
    }

    init(socket) {
        if (this._tempport.substr(0, 1) == "+") {
            this._connector = tls.connect;
            this._tempport = parseInt(socket.irc.port.toString().substr(1));
            this._ssl = true;
        }
        else if (this._tempport.substr(0, 1) == "=") {
            this._connector = tls.connect;
            this._tempport = parseInt(socket.irc.port.toString().substr(1));
            this._ssl = true;
            this._options = { rejectUnauthorized: false };
        }
        try {
            if (this._ssl)
                this.connection = this._connector(this._tempport, socket.irc.server, this._options);
            else
                this.connection = this._connector(this._tempport, socket.irc.server);
        } catch (e) {
            if (global.DEBUG) {
                console.log("Failed to connect to " + socket.irc.server + ":" + this._tempport);
            }
            this._success = false;
        }
        if (socket.connected)
            this._success = false;
        if (this._success) {
            if (global.DEBUG)
                console.log("Starting connect");
            // bouncer connections
            this.connection.parents = [];
            this.connection.parents[0] = socket;

            // client buffers
            this.connection.buffers = {};
            this.connection.buffers[socket.clientbuffer] = { data: '', connected: true, privmsgnotice: [] };
            socket.connected = true;

            // irc server connection data
            this.connection.connectbuf = '';
            this.connection.nick = socket.irc.nick;
            this.connection.nick_original = socket.irc.nick;
            this.connection.password = socket.irc.password;
            this.connection.nickpassword = socket.irc.nickpassword;
            this.connection.accountsasl = socket.irc.accountsasl;
            this.connection.user = socket.irc.user;
            this.connection.ircuser = socket.irc.user;
            this.connection.server = socket.irc.server;
            this.connection.port = socket.irc.port;
            this.connection.realname = socket.irc.realname;
            this.connection.hash = socket.hash;
            this.connection.serverpassword = socket.irc.serverpassword;
            this.connection.host = socket.host != null ? socket.host : (socket.remoteAddress.substr(0, 7) == "::ffff:" ? socket.remoteAddress.substr(7) : socket.remoteAddress);
            this.connection.umode = '';
            this.connection.motd = '';
            this.connection.channels = {};
            this.connection.authenticated = false;
            this.connection.connected = true;
            this.connection.opmode = global.BOUNCER_DEFAULT_OPMODE;
            this.connection.userhostInNames = false;
            this.connection.messagetags = false;
            this.connection.ircv3Monitor = false;
            this.connection.ircv3_extendedjoin = false;
            this.connection.quitBefore005 = null;

            // Temp Buffer
            this.connection._buffer = '';
            this.connection._getnames = {};

            this.connection.on('connect', async () => {
                this.connection.write("CAP LS 302\n");
                if (global.DEBUG)
                    console.log("CAP LS 302");
                if (global.SERVER_WEBIRC.length > 0) {
                    if (this.connection.host == ":1")
                        this.connection.host = "127.0.0.1";

                    let _reverse_ip = this.host;
                    try {
                      _reverse_ip = await reverse(this.host);
                    } catch(e) {
                    }
                    if(global.WEBIRCSPECIAL) { // My server irc
                        let isIPv6 = this.connection.host.includes(':');
                        let ip = isIPv6 ? this.connection.host.split(':').slice(0, 4).join(':') : this.connection.host;
                        let cleanIp = ip.replace(/:/g, '');
                        let md5Hash = generateMD5AndGetSubstring(cleanIp);
                        let vhost = iphash(this.connection.accountsasl) || '0';

                        let webircMessage = `WEBIRC ${global.SERVER_WEBIRC} ${this.connection.user} galaxy-${cleanIp}.ip${md5Hash.first4}${md5Hash.last4}.cloud-${vhost}.irccity.com ${this.connection.host} :secure\n`;

                        this.connection.write(webircMessage);
                    }
                    else if(global.SERVER_WEBIRCHASHIP && !global.SERVER_WEBIRCPROXY) {
                      this.connection.write('WEBIRC '+global.SERVER_WEBIRC+' '+this.connection.user+' jbnc.'+iphash(this.connection.hostonce)+" "+this.connection.host+"\n");
                    }
                    else if(global.SERVER_WEBIRCHASHIP && global.SERVER_WEBIRCPROXY) {
                      this.connection.write('WEBIRC '+global.SERVER_WEBIRC+' '+this.connection.user+' jbnc.'+iphash(this.connection.host)+" "+this.connection.host+"\n");
                    }
                    else
                      this.connection.write('WEBIRC '+global.SERVER_WEBIRC+' '+this.connection.user+' '+_reverse_ip+" "+this.connection.host+"\n");
                }
                if (this.connection.serverpassword) {
                    this.connection.write('PASS ' + this.connection.serverpassword + '\n');
                }
                this.connection.write('NICK ' + this.connection.nick + '\n');
                this.connection.write('USER ' + this.connection.user + ' * 0 :' + this.connection.realname + '\n');
                global.connections[hash(this.connection.nick_original + this.connection.password + this.connection.server + this.connection.port.toString())] = this.connection;
                if (global.DEBUG)
                    console.log("Connection created.");
            });
            this.connection.on('data', (d) => {
                let _d = this.connection._buffer + d.toString();
                let lines = _d.toString().split('\n');
                if (lines[lines.length - 1] !== '') {
                    this.connection._buffer = lines.pop();
                } else {
                    lines.pop();
                    this.connection._buffer = '';
                }

                for (let n = 0; n < lines.length; n++) {
                    if (this.connection.quitBefore005) {
                        console.log("detection du quit de Before005", this.connection.quitBefore005);
                        try {
                            global.connections[this.connection.hash].end();
                        } catch (e) { }
                        delete global.connections[this.connection.hash];
                        continue;
                    }
                    if (global.DEBUG)
                        console.log("log> " + lines[n]);
                    let data = lines[n].trim().split(" ");
                    if (data[1] == "CAP") {
                        // :irc.example.net CAP * LS :invite-notify ...
                        // :irc.example.net CAP * NEW :invite-notify ...
                        // :irc.example.net CAP testor LIST :away-notify invite-notify extended-join userhost-in-names multi-prefix cap-notify setname chghost account-notify message-tags batch server-time account-tag labeled-response

                        if (data[3] && (data[3] == 'LS' || data[3] === 'NEW')) {

                            let wantedCaps = new Set([
                                'server-time',
                                'multi-prefix',
                                'away-notify',
                                'account-notify',
                                'account-tag',
                                'invite-notify',
                                'extended-join',
                                'userhost-in-names',
                                'cap-notify',
                                'sasl',
                                'message-tags',
                            ]);

                            let offeredCaps = lines[n].trim().split(' ');


                            let requestingCaps = offeredCaps
                                .filter((cap) => (
                                    wantedCaps.has(cap.split('=')[0].toLowerCase())
                                ))
                                .map((cap) => cap.split('=')[0]);

                            if (requestingCaps.includes("userhost-in-names"))
                                this.connection.userhostInNames = true;

                            if (requestingCaps.includes("message-tags"))
                                this.connection.messagetags = true;

                            if (requestingCaps.includes("sasl"))
                                this.connection.sasl = true;

                            if (requestingCaps.includes("extended-join"))
                                this.connection.ircv3_extendedjoin = true;

                            if (data[3] !== 'NEW' && requestingCaps.length === 0) {
                                this.connection.write("CAP END\n");
                            } else {
                                this.connection.write(`CAP REQ :${requestingCaps.join(' ')}\n`);
                            }

                        }
                        else if (this.connection.sasl && data[3] && data[3] == 'ACK') {
                            this.connection.write("AUTHENTICATE PLAIN\n");
                        }
                        else {
                            if (!this.connection.sasl)
                                this.connection.write("CAP END\n");
                        }
                        continue;
                    }

                    if (this.connection.sasl && data[0] == "AUTHENTICATE" && data[1] == "+") {
                        const auth_str = (this.connection.accountsasl ? this.connection.accountsasl : this.connection.nick) + '\0' +
                            (this.connection.accountsasl ? this.connection.accountsasl : this.connection.nick) + '\0' +
                            this.connection.nickpassword;

                        const b = Buffer.from(auth_str, 'utf8');
                        const b64 = b.toString('base64');

                        const singleAuthCommandLength = 400;
                        let sliceOffset = 0;

                        while (b64.length > sliceOffset) {
                            this.connection.write('AUTHENTICATE ' + b64.substr(sliceOffset, singleAuthCommandLength) + '\n');
                            sliceOffset += singleAuthCommandLength;
                        }

                        if (b64.length === sliceOffset)
                            this.connection.write('AUTHENTICATE +\n');

                        continue;
                    }

                    // :irc.server 904 <nick> :SASL authentication failed
                    if (data[1] == "904") { // ERR_SASLFAIL
                        if (!this.connection.authenticated) {
                            this.connection.end();
                        }
                    }

                    // :x 903 y :SASL authentication successful
                    if (data[1] == "903") { // RPL_SASLLOGGEDIN
                        if (!this.connection.authenticated) {
                            this.connection.write("CAP END\n");
                        }
                    }

                    if (data[1] == "900") { // RPL_LOGGEDIN
                        this.connection.account = data[4];
                    }

                    /*if(data[1]=="901") { // RPL_LOGGEDOUT
                      this.connection.account = '';
                    }*/

                    let s = data[1];

                    if (this.connection.messagetags && global.ircCommandList.has(data[2])) {
                        s = data[2];
                    }

                    let _mode_target,
                        _target,
                        _sender,
                        _mode,
                        _mode_count,
                        _add,
                        _temp,
                        _datatemp,
                        _nick,
                        _userhost,
                        _channel,
                        __channel,
                        _channels,
                        _topic,
                        _setter,
                        _time,
                        _names,
                        _this_target,
                        _regex,
                        _new,
                        _statut
                        ;

                    switch (s) {
                        case '001': // RPL_WELCOME
                            if (!this.connection.authenticated) {
                                this.connection.authenticated = true;
                                this.connection.nick_original = data[2];
                                if (lines[n].lastIndexOf("@") > 0) {
                                    this.connection.ircuser = lines[n].substr(lines[n].lastIndexOf("!") + 1, lines[n].lastIndexOf("@") - lines[n].lastIndexOf("!") - 1);
                                    this.connection.host = lines[n].substr(lines[n].lastIndexOf("@") + 1).trim();
                                }
                                else
                                    this.connection.host = "jbnc";
                            }
                            this.connection.connectbuf += lines[n] + "\n";
                            break;
                        case '002': // RPL_YOURHOST
                            this.connection.connectbuf += lines[n] + "\n";
                            break;
                        case '003': // RPL_CREATED
                            this.connection.connectbuf += lines[n] + "\n";
                            break;
                        case '004': // RPL_MYINFO
                            this.connection.connectbuf += lines[n] + "\n";
                            break;
                        case '005': // RPL_ISUPPORT
                            this.connection.connectbuf += lines[n] + "\n";
                            this.connection.quitBefore005 = false;
                            break;
                        case '324': // RPL_CHANNELMODEIS
                        case 'MODE':
                            _mode_target = [];
                            // <- :irc.jbnc.com 324 spawn #channel +CPTVnrst
                            if (data[1] == '324') {
                                _target = data[3].trim();
                                _sender = data[0].substr(1).split("!")[0];
                                _mode = data[4].trim();
                                if (data[5])
                                    _mode_target = data.slice(5, data.length);
                            }
                            // <- @time=2020-09-16T22:25:40.594Z :spawn!spawn@chanroot/b3Az MODE #channel +m
                            else if (this.connection.messagetags && data[2] == 'MODE') {
                                _target = data[3].trim();
                                _sender = data[1].substr(1).split("!")[0];
                                _mode = data[4].trim();
                                if (data[5])
                                    _mode_target = data.slice(5, data.length);
                            }
                            // :spawn!spawn@chanroot/b3Az MODE #channel +m
                            else if (!this.connection.messagetags && data[1] == 'MODE') {
                                _target = data[2].trim();
                                _sender = data[0].substr(1).split("!")[0];
                                _mode = data[3].trim();
                                if (data[4])
                                    _mode_target = data.slice(4, data.length);
                            }
                            else {
                                _target = data[2].trim();
                                _sender = data[0].substr(1).split("!")[0];
                                _mode = data[3].trim();
                                if (data[4])
                                    _mode_target = data.slice(4, data.length);
                            }

                            _mode = _mode.indexOf(":") != -1 ? _mode.substr(1) : _mode;

                            _mode_count = 0;
                            _add = true;
                            // walk thru modes
                            for (let i = 0; i < _mode.length; i++) {
                                let curchan = this.connection.channels[_target.toLowerCase()];
                                if (_mode[i] == '+')
                                    _add = true;
                                else if (_mode[i] == '-')
                                    _add = false;
                                else {
                                    if (_add) {
                                        if (_sender == _target && _target == this.connection.nick || _sender == "NickServ" && _target == this.connection.nick || _sender == "OperServ" && _target == this.connection.nick) {
                                            if (this.connection.umode != null && this.connection.umode.indexOf(_mode[i]) == -1) {
                                                this.connection.umode += _mode[i];
                                            }
                                        }
                                        else if (curchan != null && (_mode[i] != 'o' && _mode[i] != 'k' && _mode[i] != 'v' && _mode[i] != 'h' && _mode[i] != 'l')) {
                                            if (curchan.modes != null && curchan.modes.indexOf(_mode[i]) == -1)
                                                curchan.modes += _mode[i];
                                        }
                                        else if ((_target.indexOf("#") != -1 || _target.indexOf("&") != -1) && (_mode[i] == 'o' || _mode[i] == 'k' || _mode[i] == 'v' || _mode[i] == 'h' || _mode[i] == 'l' ||
                                            _mode[i] == 'e' || _mode[i] == 'b' || _mode[i] == 'I' || _mode[i] == 'q' || _mode[i] == 'f' ||
                                            _mode[i] == 'j')) {
                                            if (_mode[i] == 'o' || _mode[i] == 'v' || _mode[i] == 'h') {
                                                if (curchan && curchan.names) {
                                                    for (let c = 0; c < curchan.names.length; c++) {
                                                        if (curchan.names[c].replace(/(&|~|@|%|\+)/, "") == _mode_target[_mode_count]) {
                                                            switch (_mode[i]) {
                                                                case 'o':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    if (curchan.names[c].indexOf("@") == -1) {
                                                                        curchan.names[c] = "@" + curchan.names[c];
                                                                        if (_mode_target[_mode_count] != this.connection.nick && curchan.aop && curchan.aop.indexOf(_this_target) < 0 && this.connection.opmode) {
                                                                            curchan.aop.push(_this_target);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) curchan.isop = true;
                                                                    break;
                                                                case 'v':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    if (curchan.names[c].indexOf("+") == -1) {
                                                                        if (curchan.names[c].indexOf("&") == -1 || curchan.names[c].indexOf("~") == -1 || curchan.names[c].indexOf("@") == -1) {
                                                                            if (curchan.names[c].indexOf("%") == -1) {
                                                                                curchan.names[c] = "+" + curchan.names[c];
                                                                            }
                                                                            else {
                                                                                curchan.names[c] = curchan.names[c].substr(0, 1) + "+" + curchan.names[c].substr(1);
                                                                            }
                                                                        }
                                                                        else {
                                                                            if (curchan.names[c].indexOf("%") == -1) {
                                                                                curchan.names[c] = curchan.names[c].substr(0, 1) + "+" + curchan.names[c].substr(1);
                                                                            }
                                                                            else {
                                                                                curchan.names[c] = curchan.names[c].substr(0, 2) + "+" + curchan.names[c].substr(2);
                                                                            }
                                                                        }
                                                                        if (_mode_target[_mode_count] != this.connection.nick && curchan.aov && curchan.aov.indexOf(_this_target) < 0 && this.connection.opmode) {
                                                                            curchan.aov.push(_mode_target[_this_target]);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) curchan.isvoice = true;
                                                                    break;
                                                                case 'h':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    if (curchan.names[c].indexOf("%") == -1) {
                                                                        if (curchan.names[c].indexOf("&") == -1 || curchan.names[c].indexOf("~") == -1 || curchan.names[c].indexOf("@") == -1) {
                                                                            curchan.names[c] = "%" + curchan.names[c];
                                                                        }
                                                                        else
                                                                            curchan.names[c] = curchan.names[c].substr(0, 1) + "%" + curchan.names[c].substr(1);
                                                                        if (_mode_target[_mode_count] != this.connection.nick && curchan.aoh && curchan.aoh.indexOf(_this_target) < 0 && this.connection.opmode) {
                                                                            curchan.aoh.push(_mode_target[_this_target]);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) curchan.ishop = true;
                                                                    break;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    //console.error("curchan or curchan.names is undefined.");
                                                }
                                                _mode_count++;
                                                continue;
                                            }
                                            else {
                                                if (_mode[i] == 'k')
                                                    curchan.key = _mode_target[_mode_count];
                                                else if (_mode[i] == 'l')
                                                    curchan.limit = _mode_target[_mode_count];
                                                else if (_mode[i] == 'f')
                                                    curchan.forward = _mode_target[_mode_count];
                                                else if (_mode[i] == 'j')
                                                    curchan.throttle = _mode_target[_mode_count];

                                                if (curchan.modes.indexOf(_mode[i]) == -1)
                                                    curchan.modes += _mode[i];
                                                _mode_count++;
                                            }
                                        }
                                    }
                                    else {
                                        _regex = new RegExp(_mode[i], "g");
                                        if (_sender == _target && _target == this.connection.nick || _sender == "NickServ" && _target == this.connection.nick || _sender == "OperServ" && _target == this.connection.nick)
                                            this.connection.umode = this.connection.umode.replace(_regex, "");
                                        else if (curchan != null && (_mode[i] != 'o' && _mode[i] != 'v' && _mode[i] != 'h') && curchan.modes)
                                            curchan.modes = curchan.modes.replace(_regex, "");
                                        if ((_target.indexOf("#") != -1 || _target.indexOf("&") != -1) && (_mode[i] == 'o' || _mode[i] == 'k' || _mode[i] == 'v' || _mode[i] == 'h' || _mode[i] == 'l' ||
                                            _mode[i] == 'e' || _mode[i] == 'b' || _mode[i] == 'I' || _mode[i] == 'q' || _mode[i] == 'f' ||
                                            _mode[i] == 'j')) {
                                            if (_mode[i] == 'o' || _mode[i] == 'v' || _mode[i] == 'h') {
                                                if (curchan && curchan.names) {
                                                    for (let c = 0; c < curchan.names.length; c++) {
                                                        if (curchan.names[c].replace(/(&|~|@|%|\+)/, "") == _mode_target[_mode_count]) {
                                                            switch (_mode[i]) {
                                                                case 'o':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    curchan.names[c] = curchan.names[c].replace(/(&|~|@)/, "");
                                                                    if (_mode_target[_mode_count] != this.connection.nick && curchan.aop && curchan.aop.indexOf(_this_target) >= 0 && this.connection.opmode) {
                                                                        curchan.aop.splice(curchan.aop.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) this.connection.isop = false;
                                                                    break;
                                                                case 'v':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    curchan.names[c] = curchan.names[c].replace("+", "");
                                                                    if (_mode_target[_mode_count] != this.connection.nick && curchan.aov && curchan.aov.indexOf(_this_target) >= 0 && this.connection.opmode) {
                                                                        curchan.aov.splice(curchan.aov.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) this.connection.isvoice = false;
                                                                    break;
                                                                case 'h':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    curchan.names[c] = curchan.names[c].replace("%", "");
                                                                    if (_mode_target[_mode_count] != this.connection.nick && curchan.aoh && curchan.aoh.indexOf(_this_target) >= 0 && this.connection.opmode) {
                                                                        curchan.aoh.splice(curchan.aoh.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.connection.nick) this.connection.ishop = false;
                                                                    break;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    //console.error("curchan or curchan.names is undefined.");
                                                }
                                                _mode_count++;
                                                continue;
                                            }
                                            else {
                                                if (_mode[i] == 'k') {
                                                    curchan.key = null;
                                                    _mode_count++;
                                                }
                                                else if (_mode[i] == 'l')
                                                    curchan.limit = null;
                                                else if (_mode[i] == 'j')
                                                    curchan.throttle = null;
                                                else if (_mode[i] == 'f')
                                                    curchan.forward = null;
                                            }
                                        }

                                    }
                                }
                            }
                            break;
                        case '375': // RPL_MOTDSTART
                            this.connection.motd = '';
                            break;
                        case '372': // RPL_MOTD
                            this.connection.motd += lines[n] + "\n";
                            //this.connection.motd='';
                            break;
                        case '376': // RPL_ENDOFMOTD
                            this.connection.motd += lines[n] + "\n";
                            //this.connection.motd='';
                            break;
                        case 'JOIN':
                            // <- @msgid=pHZAZJUGTgmdLbzMnFYZ5l-xBZH2fjfPCVLEsLqwDqtsA;time=2022-07-19T17:21:44.038Z :nick!ident@host JOIN #channel * :<realname>
                            _temp = (this.connection.messagetags ? data[1].substr(1).split("!") : data[0].substr(1).split("!"));
                            _datatemp = (this.connection.messagetags ? 3 : 2);
                            _nick = _temp[0];
                            if (_temp[1])
                                _userhost = _temp[1];
                            if (_temp[1] && this.connection.nick == _nick) {
                                this.connection.ircuser = _temp[1].split("@")[0];
                            }
                            _channels = data[_datatemp].substr(0).trim().split(",");
                            if (data[_datatemp].indexOf(":") != -1)
                                _channels = data[_datatemp].substr(1).trim().split(",");
                            /*
                            //console.log("debug channels: %s - nick: %s - ircuser: %s - userhost: %s", _channels, _nick, this.connection.ircuser, _userhost);
                            //process.exit(1);
                            */
                            for (let x = 0; x < _channels.length; x++) {
                                _channel = _channels[x];
                                __channel = _channel.toLowerCase();
                                if (_nick == this.connection.nick) {
                                    if (!this.connection.channels[__channel]) {
                                        //console.error("Log Join "+this.connection.messagetags+" :", lines[n]);
                                        this.connection.channels[__channel] = {
                                            modes: '',
                                            topic: '',
                                            topic_set: '',
                                            topic_time: 0,
                                            key: null,
                                            limit: null,
                                            forward: null,
                                            throttle: null,
                                            names: [],
                                            userhosts: [],
                                            name: _channel,
                                            aop: [],
                                            aoh: [],
                                            aov: [],
                                            isop: false,
                                            ishop: false,
                                            isvoice: false
                                        };
                                    }
                                    else if (this.connection.channels[__channel]) {
                                        // Appears to never be executed
                                        this.connection.channels[__channel].name = _channel;
                                    }
                                    //this.connection.write(`MODE ${_channel}\n`);
                                }
                                else {
                                    if (this.connection.channels[__channel]) {
                                        this.connection.channels[__channel].name = _channel;
                                        this.connection.channels[__channel].names.push(_nick);
                                        this.connection.channels[__channel].userhosts.push(_userhost ? _userhost : "*@*");
                                        if (this.connection.channels[__channel].isop && this.connection.channels[__channel].aop && this.connection.channels[__channel].aop.indexOf(_nick + "!" + _userhost) >= 0 && this.connection.opmode) {
                                            this.connection.write(`MODE ${this.connection.channels[__channel].name} +o ${_nick}\n`);
                                        }
                                        if ((this.connection.channels[__channel].isop || this.connection.channels[__channel].ishop) && this.connection.channels[__channel].aoh && this.connection.channels[__channel].aoh.indexOf(_nick + "!" + _userhost) >= 0 && this.connection.opmode) {
                                            this.connection.write(`MODE ${this.connection.channels[__channel].name} +h ${_nick}\n`);
                                        }
                                        if ((this.connection.channels[__channel].isop || this.connection.channels[__channel].ishop) && this.connection.channels[__channel].aov && this.connection.channels[__channel].aov.indexOf(_nick + "!" + _userhost) >= 0 && this.connection.opmode) {
                                            this.connection.write(`MODE ${this.connection.channels[__channel].name} +v ${_nick}\n`);
                                        }
                                    }
                                }
                            }
                            break;
                        case 'TOPIC':
                            _target = data[2].toLowerCase().trim();
                            _topic = lines[n].substr(lines[n].substr(1).indexOf(":") + 2).trim();
                            if (this.connection.channels[_target]) {
                                this.connection.channels[_target].topic = _topic;
                                this.connection.channels[_target].topic_set = data[0].substr(1).split("!")[0];
                                this.connection.channels[_target].topic_time = Math.floor(new Date() / 1000);
                            }
                            break;
                        case '332': // RPL_TOPIC
                            _target = data[3].toLowerCase().trim();
                            _topic = lines[n].substr(lines[n].substr(1).indexOf(":") + 2).trim();
                            if (!this.connection.channels[_target])
                                this.connection.channels[_target] = {};
                            this.connection.channels[_target].topic = _topic;
                            break;
                        case '333': // RPL_TOPICWHOTIME
                            _channel = data[3].toLowerCase().trim();
                            _setter = data[4].split("!")[0].trim();
                            _time = data[5].trim();
                            if (!this.connection.channels[_channel])
                                this.connection.channels[_channel] = {};
                            this.connection.channels[_channel].topic_set = _setter;
                            this.connection.channels[_channel].topic_time = _time;
                            break;
                        case 'KICK':
                            _target = (this.connection.messagetags ? data[4].trim() : data[3].trim());
                            _channel = (this.connection.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
                            if (_target == this.connection.nick) {
                                delete this.connection.channels[_channel];
                            }
                            else if (this.connection.channels[_channel]) {
                                for (let x = 0; x < this.connection.channels[_channel].names.length; x++) {
                                    if (this.connection.channels[_channel].names[x].replace(/(&|~|@|%|\+)/, "") == _target)
                                        break;
                                    this.connection.channels[_channel].names.splice(x, 1);
                                }
                            }
                            break;
                        case 'PART':
                            _target = (this.connection.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
                            _sender = (this.connection.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
                            if (_sender == this.connection.nick) {
                                delete this.connection.channels[_target];
                            }
                            else if (this.connection.channels[_target]) {
                                for (let x = 0; x < this.connection.channels[_target].names.length; x++) {
                                    if (this.connection.channels[_target].names[x].replace(/(&|~|@|%|\+)/, "") == _sender)
                                        break;
                                    this.connection.channels[_target].names.splice(x, 1);
                                    this.connection.channels[_target].userhosts.splice(x, 1);
                                }
                            }
                            break;
                        case 'QUIT':
                            _sender = (this.connection.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
                            for (let key in this.connection.channels) {
                                if (Object.prototype.hasOwnProperty.call(this.connection.channels, key)) {
                                    for (let x = 0; x < this.connection.channels[key].names.length; x++) {
                                        if (this.connection.channels[key].names[x].replace(/(&|~|@|%|\+)/, "") == _sender) {
                                            this.connection.channels[key].names.splice(x, 1);
                                            this.connection.channels[key].userhosts.splice(x, 1);
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        case '353': // RPL_NAMEREPLY
                            _channel = data[4].toLowerCase().trim();
                            _names = lines[n].substr(1).split(" :")[1].trim().split(" ");
                            if (!this.connection.channels[_channel])
                                break;
                            if (!this.connection._getnames[_channel]) {
                                this.connection._getnames[_channel] = true;
                                if (!this.connection.channels[_channel]) {
                                    this.connection.channels[_channel] = {};
                                }
                                this.connection.channels[_channel].names = [];
                            }
                            for (let x = 0; x < _names.length; x++) {
                                if (!this.connection.channels[_channel])
                                    break;
                                this.connection.channels[_channel].names.push(_names[x].trim().split("!")[0]);

                                if (typeof this.connection.channels[_channel].userhosts === 'undefined')
                                    this.connection.channels[_channel].userhosts = [];

                                if (_names[x].trim().indexOf("!") >= 0)
                                    this.connection.channels[_channel].userhosts.push(_names[x].trim().split("!")[1]);
                                /*else
                                  this.connection.channels[_channel].userhosts.push("*@*");	*/
                            }
                            break;
                        case '366': // RPL_ENDOFBANLIST
                            _channel = data[3].toLowerCase().trim();
                            this.connection._getnames[_channel] = false;
                            break;
                        case 'NICK':
                            _sender = data[1].substr(1).split("!")[0];
                            _new = data[3].substr(1).trim();

                            if (_sender == this.connection.nick) {
                                this.connection.nick = _new;
                            }

                            for (let key in this.connection.channels) {
                                if (Object.prototype.hasOwnProperty.call(this.connection.channels, key)) {
                                    for (let x = 0; x < this.connection.channels[key].names.length; x++) {
                                        if (this.connection.channels[key].names[x].replace(/(&|~|@|%|\+)/, "") == _sender) {
                                            _statut = (/^(&|~|@|%|\+)/.test(this.connection.channels[key].names[x].substr(0, 1)) ? this.connection.channels[key].names[x].substr(0, 1) : "");
                                            this.connection.channels[key].names.splice(x, 1);
                                            this.connection.channels[key].names.push(_statut + _new);
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        case '433': // ERR_NICKNAMEINUSE
                            if (this.connection.parents.length == 0) {
                                if (data[2] == '*') {
                                    if (global.DEBUG)
                                        console.log("Une erreur 433 est détecté, un quit ?");
                                    this.connection.end();
                                    /*this.write("NICK "+data[3].trim()+"_"+"\n");
                                    this.nick=data[3].trim()+"_";*/
                                }
                            }
                            break;
                        case '451': // ERR_NOTREGISTERED
                            if (this.connection.parents.length == 0) {
                                if (data[2] == '*') {
                                    if (global.DEBUG)
                                        console.log("Une erreur 451 est détecté, un quit ?");
                                    this.connection.end();
                                    /*this.write("NICK "+data[3].trim()+"_"+"\n");
                                    this.nick=data[3].trim()+"_";*/
                                }
                            }
                            break;
                    }
                    if (data[1] == "PING") {
                        this.connection.write("PONG " + data[2].substr(1).trim() + "\n");
                        continue;
                    }
                    if (data[0] == "PING") {
                        this.connection.write("PONG " + data[1].substr(1).trim() + "\n");
                        continue;
                    }
                    if (data[0] == "ERROR") {
                        if (this.connection.gone) {
                            clearTimeout(this.connection.gone);
                            this.connection.gone = null;
                        }
                    }
                    if (lines[n].length > 1) {
                        for (let m = 0; m < this.connection.parents.length; m++) {
                            this.connection.parents[m].write(lines[n] + "\n");
                        }
                    }

                    // Check the last 400 messages that will be sent on the irc web client to sort the new messages
                    if (global.MSG_REDISTRIBUTION && this.connection.messagetags && lines[n].startsWith("@")) {


                        /*
                        > @realname=17/H/01/cell/Dnc;account=Jordan59400;msgid=m90TSwrqZQDN5Vk0bXrj7R;time=2023-11-02T14:20:42.421Z :nick!ident@host AWAY :away-1698934842
                        > @realname=13/H/fr/Dnc;account=Theolg;msgid=TeuM0xmV7dwFr8TZhN1gLG;time=2023-11-02T14:20:47.356Z :nick!ident@host AWAY
                        > @realname=17/H/35;msgid=gG5yPU6i2oNEbchageyGoP-wuLL37AsrC3pbMcU4QJcHg;time=2023-11-02T14:20:52.856Z :nick!ident@host QUIT :Googlebye
                        */
                        /*
                            result_messagetags = lines[n].split(" ")[0]; // @time=2020-12-31T05:46:20.951Z;msgid=bUxJGIgyI3Xafw42ccbHTd;account=Sympa
                            nick: line.split(" ")[1].substr(1).split("!")[0]
                            ident: line.split(" ")[1].substr(1).split("!")[1].split("@")[0]
                            hostname: line.split(" ")[1].substr(1).split("!")[1].split("@")[1]
                            cmd: line.split(" ")[2]
                            target: line.split(" ")[3]
                            message: line.split(" ").splice(4).join(' ').substr(1)
                            account: result_messagetags.split(";")[2].split("=")[1]
                            time: result_messagetags.split(";")[0].replace("@time=","")
                            msgid: result_messagetags.split(";")[1].split("=")[1]
                        */

                        // Ignore CTCP request/responses
                        if (
                            (lines[n].split(" ")[2] === 'PRIVMSG' || lines[n].split(" ")[2] === 'NOTICE') &&
                            lines[n].split(" ").splice(4).join(' ').substr(1) && lines[n].split(" ").splice(4).join(' ').substr(1)[0] === '\x01'
                        ) {
                            // We do want to log ACTIONs though
                            if (!lines[n].split(" ").splice(4).join(' ').substr(1).startsWith('\x01ACTION ')) {
                                if (global.DEBUG)
                                    console.log("Ignoring CTCP");
                                // return; - Seems to freeze the joints on the channels (not sure)
                                continue;
                            }
                        }

                        if (lines[n].split(" ")[2] === "PRIVMSG" || lines[n].split(" ")[2] === "NOTICE") {
                            for (let key in this.connection.buffers) {
                                if (Object.prototype.hasOwnProperty.call(this.connection.buffers, key)) {
                                    let _n = lines[n].split(" ")[3]; // PRIVMSG <hereTarget> :... - Channel name or PV name

                                    let message = lines[n];
                                    let atIndex1 = message.indexOf(" :");
                                    let atIndex2 = message.indexOf("!");
                                    let source = message.substring(atIndex1 + 2, atIndex2);
                                    let count = 0;

                                    for (let x = 0; x < this.connection.buffers[key].privmsgnotice.length; x++) {
                                        if (this.connection.buffers[key].privmsgnotice[x].target === _n) {
                                            count++;

                                            if (count >= 300) {
                                                this.connection.buffers[key].privmsgnotice.splice(x, 1);
                                                break;
                                            }
                                        }
                                    }

                                    // Adding all messages
                                    this.connection.buffers[key].privmsgnotice.push({
                                        source: source,
                                        target: _n,
                                        line: lines[n] + "\n"
                                    });
                                }
                            }
                        }
                        else if (lines[n].split(" ")[2] && global.ircCommandRedistributeMessagesOnConnect.has(lines[n].split(" ")[2].trimEnd())) {
                            for (let key in this.connection.buffers) {
                                if (Object.prototype.hasOwnProperty.call(this.connection.buffers, key)) {
                                    let _n = "server.irc";
                                    let count = 0;

                                    for (let x = 0; x < this.connection.buffers[key].privmsgnotice.length; x++) {
                                        if (this.connection.buffers[key].privmsgnotice[x].target === _n) {
                                            count++;

                                            if (count >= 300) {
                                                this.connection.buffers[key].privmsgnotice.splice(x, 1);
                                                break;
                                            }
                                        }
                                    }

                                    // Adding all messages
                                    this.connection.buffers[key].privmsgnotice.push({
                                        target: _n,
                                        line: lines[n] + "\n"
                                    });
                                }
                            }
                        }

                        //}



                    }
                    // store clientbuf if not connected
                    else if (lines[n].indexOf("PRIVMSG") >= 0 || lines[n].indexOf("NOTICE") >= 0 || lines[n].indexOf("WALLOPS") >= 0 || lines[n].indexOf("GLOBOPS") >= 0 || lines[n].indexOf("CHATOPS") >= 0) {
                        for (let key in this.connection.buffers) {
                            if (Object.prototype.hasOwnProperty.call(this.connection.buffers, key)) {
                                if (!this.connection.buffers[key].connected) {
                                    this.connection.buffers[key].data += lines[n] + "\n";

                                    // Temporary: replace this system with "PRIVMSG_LINEMAX" ...
                                    let _split = this.connection.buffers[key].data.split("\n");
                                    if (_split.length >= global.BUFFER_LINEMAX && global.BUFFER_LINEMAX != 0) {
                                        _split.splice(0, _split.length - global.BUFFER_LINEMAX);
                                        let _line = "";
                                        for (let t = 0; t < _split.length; t++) {
                                            _line += _split[t] + "\n";
                                        }
                                        this.connection.buffers[key].data = _line;
                                    }
                                }
                            }
                        }
                    }
                }

            });
            this.connection.on('close', () => {
                for (let x = 0; x < this.connection.parents.length; x++) {
                    clearInterval(this.connection.parents[x].pings);
                    this.connection.parents[x].write(":" + this.connection.nick + " QUIT :QUIT");
                    this.connection.parents[x].end();
                }
                this.connection.buffers = false;
                delete global.connections[hash(this.connection.nick + this.connection.password + this.connection.server + this.connection.port.toString())];
                this.connection.destroy();
            });
            this.connection.on('error', () => {
                this.connection.end();
            });
            this.connection.on('end', () => {
                console.log('Connection finished : connection');
                return;
            });
        }
        else {
            socket.end();
        }
    }



}

// Helper Functions
function hash(data) {
    return crypto.createHash('sha256').update(data, 'utf8').digest('base64');
}
function iphash(data) {
    return crypto.createHash('md5').update(data).digest('hex').substring(0, 6);
}
function generateMD5AndGetSubstring(data) {
    const md5Hash = crypto.createHash('md5').update(data).digest('hex');
    // Get the first 4 and last 4 characters of the hash
    const first4Characters = md5Hash.slice(0, 4);
    const last4Characters = md5Hash.slice(-4);
    return {
        first4: first4Characters,
        last4: last4Characters
    };
}


module.exports = ClientConnect;
