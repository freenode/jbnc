
/*global global, module, require*/
/*eslint no-undef: "error"*/

const tls = require('tls');
const net = require('net');
const dns = require('dns');
const reverse = require('util').promisify(dns.reverse);
const crypto = require("crypto");

class ClientConnect {
    constructor(socket, client) {
        this.connections = client.connections;
        this.client = client;
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
                this.client = this._connector(this._tempport, socket.irc.server, this._options);
            else
                this.client = this._connector(this._tempport, socket.irc.server);
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
            this.client.parents = [];
            this.client.parents[0] = socket;

            // client buffers
            this.client.buffers = {};
            this.client.buffers[socket.clientbuffer] = { data: '', connected: true, privmsgnotice: [] };
            socket.connected = true;

            // irc server connection data
            this.client.connectbuf = '';
            this.client.nick = socket.irc.nick;
            this.client.nick_original = socket.irc.nick;
            this.client.password = socket.irc.password;
            this.client.nickpassword = socket.irc.nickpassword;
            this.client.accountsasl = socket.irc.accountsasl;
            this.client.user = socket.irc.user;
            this.client.ircuser = socket.irc.user;
            this.client.server = socket.irc.server;
            this.client.port = socket.irc.port;
            this.client.realname = socket.irc.realname;
            this.client.hash = socket.hash;
            this.client.serverpassword = socket.irc.serverpassword;
            this.client.host = socket.host != null ? socket.host : (socket.remoteAddress.substr(0, 7) == "::ffff:" ? socket.remoteAddress.substr(7) : socket.remoteAddress);
            this.client.vhost = false;
            this.client.umode = '';
            this.client.motd = '';
            this.client.channels = {};
            this.client.authenticated = false;
            this.client.connected = true;
            this.client.opmode = global.BOUNCER_DEFAULT_OPMODE;
            this.client.userhostInNames = false;
            this.client.messagetags = false;
            this.client.ircv3Monitor = false;
            this.client.ircv3_extendedjoin = false;
            this.client.gone='';
            this.client.goneTime='';
            this.client.users = -1;
            this.client.sessionConnections = 0;

            // Default is null, false is reconnecting, and true is disconnected before 005.
            this.client.preConnectionLogout = false;

            // Temp Buffer
            this.client._buffer = '';
            this.client._getnames = {};

            this.client.on('connect', async () => {
                this.client.write("CAP LS 302\n");
                if (global.DEBUG)
                    console.log("CAP LS 302");
                if (global.SERVER_WEBIRC.length > 0) {
                    if (this.client.host == ":1")
                        this.client.host = "127.0.0.1";

                    let _reverse_ip = this.host;
                    try {
                        _reverse_ip = await reverse(this.host);
                    } catch (e) {
                    }
                    if (global.WEBIRCSPECIAL) { // My server irc
                        let isIPv6 = this.client.host.includes(':');
                        let ip = isIPv6 ? this.client.host.split(':').slice(0, 4).join(':') : this.client.host;
                        let cleanIp = ip.replace(/:/g, '');
                        let md5Hash = generateMD5AndGetSubstring(cleanIp);
                        let vhost = iphash(this.client.accountsasl) || '0';

                        let webircMessage = `WEBIRC ${global.SERVER_WEBIRC} ${this.client.user} galaxy-${cleanIp}.ip${md5Hash.first4}${md5Hash.last4}.cloud-${vhost}.irccity.com ${this.client.host} :secure\n`;

                        this.client.write(webircMessage);
                    }
                    else if (global.SERVER_WEBIRCHASHIP && !global.SERVER_WEBIRCPROXY) {
                        this.client.write('WEBIRC ' + global.SERVER_WEBIRC + ' ' + this.client.user + ' jbnc.' + iphash(this.client.hostonce) + " " + this.client.host + "\n");
                    }
                    else if (global.SERVER_WEBIRCHASHIP && global.SERVER_WEBIRCPROXY) {
                        this.client.write('WEBIRC ' + global.SERVER_WEBIRC + ' ' + this.client.user + ' jbnc.' + iphash(this.client.host) + " " + this.client.host + "\n");
                    }
                    else
                        this.client.write('WEBIRC ' + global.SERVER_WEBIRC + ' ' + this.client.user + ' ' + _reverse_ip + " " + this.client.host + "\n");
                }
                if (this.client.serverpassword) {
                    this.client.write('PASS ' + this.client.serverpassword + '\n');
                }
                this.client.write('NICK ' + this.client.nick + '\n');
                this.client.write('USER ' + this.client.user + ' * 0 :' + this.client.realname + '\n');
                this.connections[hash(this.client.nick_original + this.client.password + this.client.server + this.client.port.toString())] = this.client;
                if (global.DEBUG)
                    console.log("Connection created.");
            });
            this.client.on('data', (d) => {
                let _d = this.client._buffer + d.toString();
                let lines = _d.toString().split('\r\n');
                if (lines[lines.length - 1] !== '') {
                    this.client._buffer = lines.pop();
                } else {
                    lines.pop();
                    this.client._buffer = '';
                }

                for (let n = 0; n < lines.length; n++) {
                    if (this.client.preConnectionLogout) {
                        console.log("detection du quit avant Before005", this.client.preConnectionLogout);
                        try {
                            this.connections[this.client.hash].end();
                        } catch (e) { }
                        delete this.connections[this.client.hash];
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
                                this.client.userhostInNames = true;

                            if (requestingCaps.includes("message-tags"))
                                this.client.messagetags = true;

                            if (requestingCaps.includes("sasl"))
                                this.client.sasl = true;

                            if (requestingCaps.includes("extended-join"))
                                this.client.ircv3_extendedjoin = true;

                            if (data[3] !== 'NEW' && requestingCaps.length === 0) {
                                //this.client.write("CAP END\n");
                            } else {
                                this.client.write(`CAP REQ :${requestingCaps.join(' ')}\n`);
                            }

                        }
                        else if (this.client.sasl && data[3] && data[3] == 'ACK') {
                            this.client.write("AUTHENTICATE PLAIN\n");
                        }
                        else {
                            if (!this.client.sasl)
                                this.client.write("CAP END\n");
                        }
                        continue;
                    }

                    if (this.client.sasl && data[0] == "AUTHENTICATE" && data[1] == "+") {
                        const auth_str = (this.client.accountsasl ? this.client.accountsasl : this.client.nick) + '\0' +
                            (this.client.accountsasl ? this.client.accountsasl : this.client.nick) + '\0' +
                            this.client.nickpassword;

                        const b = Buffer.from(auth_str, 'utf8');
                        const b64 = b.toString('base64');

                        const singleAuthCommandLength = 400;
                        let sliceOffset = 0;

                        while (b64.length > sliceOffset) {
                            this.client.write('AUTHENTICATE ' + b64.substr(sliceOffset, singleAuthCommandLength) + '\n');
                            sliceOffset += singleAuthCommandLength;
                        }

                        if (b64.length === sliceOffset)
                            this.client.write('AUTHENTICATE +\n');

                        continue;
                    }

                    // :irc.server 904 <nick> :SASL authentication failed
                    if (data[1] == "904") { // ERR_SASLFAIL
                        if (!this.client.authenticated) {
                            this.client.end();
                        }
                    }

                    // :x 903 y :SASL authentication successful
                    if (data[1] == "903") { // RPL_SASLLOGGEDIN
                        if (!this.client.authenticated) {
                            this.client.write("CAP END\n");
                        }
                    }

                    if (data[1] == "900") { // RPL_LOGGEDIN
                        this.client.account = data[4];
                    }

                    /*if(data[1]=="901") { // RPL_LOGGEDOUT
                      this.client.account = '';
                    }*/

                    let s = data[1];

                    if (this.client.messagetags && global.ircCommandList.has(data[2])) {
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
                            if (!this.client.authenticated) {
                                this.client.authenticated = true;
                                this.client.users=1;
                                this.client.sessionConnections=1;
                                this.client.nick_original = data[2];
                                if (lines[n].lastIndexOf("@") > 0) {
                                    this.client.ircuser = lines[n].substr(lines[n].lastIndexOf("!") + 1, lines[n].lastIndexOf("@") - lines[n].lastIndexOf("!") - 1);
                                    this.client.host = lines[n].substr(lines[n].lastIndexOf("@") + 1).trim();
                                }
                                else
                                    this.client.host = "jbnc";
                            }
                            this.client.connectbuf += lines[n] + "\n";
                            break;
                        case '002': // RPL_YOURHOST
                            this.client.connectbuf += lines[n] + "\n";
                            break;
                        case '003': // RPL_CREATED
                            this.client.connectbuf += lines[n] + "\n";
                            break;
                        case '004': // RPL_MYINFO
                            this.client.connectbuf += lines[n] + "\n";
                            break;
                        case '005': // RPL_ISUPPORT
                            this.client.connectbuf += lines[n] + "\n";
                            this.client.preConnectionLogout = null;
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
                            else if (this.client.messagetags && data[2] == 'MODE') {
                                _target = data[3].trim();
                                _sender = data[1].substr(1).split("!")[0];
                                _mode = data[4].trim();
                                if (data[5])
                                    _mode_target = data.slice(5, data.length);
                            }
                            // :spawn!spawn@chanroot/b3Az MODE #channel +m
                            else if (!this.client.messagetags && data[1] == 'MODE') {
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
                                let curchan = this.client.channels[_target.toLowerCase()];
                                if (_mode[i] == '+')
                                    _add = true;
                                else if (_mode[i] == '-')
                                    _add = false;
                                else {
                                    if (_add) {
                                        if (_sender == _target && _target == this.client.nick || _sender == "NickServ" && _target == this.client.nick || _sender == "OperServ" && _target == this.client.nick) {
                                            if (this.client.umode != null && this.client.umode.indexOf(_mode[i]) == -1) {
                                                this.client.umode += _mode[i];
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
                                                                        if (_mode_target[_mode_count] != this.client.nick && curchan.aop && curchan.aop.indexOf(_this_target) < 0 && this.client.opmode) {
                                                                            curchan.aop.push(_this_target);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) curchan.isop = true;
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
                                                                        if (_mode_target[_mode_count] != this.client.nick && curchan.aov && curchan.aov.indexOf(_this_target) < 0 && this.client.opmode) {
                                                                            curchan.aov.push(_mode_target[_this_target]);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) curchan.isvoice = true;
                                                                    break;
                                                                case 'h':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    if (curchan.names[c].indexOf("%") == -1) {
                                                                        if (curchan.names[c].indexOf("&") == -1 || curchan.names[c].indexOf("~") == -1 || curchan.names[c].indexOf("@") == -1) {
                                                                            curchan.names[c] = "%" + curchan.names[c];
                                                                        }
                                                                        else
                                                                            curchan.names[c] = curchan.names[c].substr(0, 1) + "%" + curchan.names[c].substr(1);
                                                                        if (_mode_target[_mode_count] != this.client.nick && curchan.aoh && curchan.aoh.indexOf(_this_target) < 0 && this.client.opmode) {
                                                                            curchan.aoh.push(_mode_target[_this_target]);
                                                                        }
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) curchan.ishop = true;
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
                                        if (_sender == _target && _target == this.client.nick || _sender == "NickServ" && _target == this.client.nick || _sender == "OperServ" && _target == this.client.nick)
                                            this.client.umode = this.client.umode.replace(_regex, "");
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
                                                                    if (_mode_target[_mode_count] != this.client.nick && curchan.aop && curchan.aop.indexOf(_this_target) >= 0 && this.client.opmode) {
                                                                        curchan.aop.splice(curchan.aop.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) this.client.isop = false;
                                                                    break;
                                                                case 'v':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    curchan.names[c] = curchan.names[c].replace("+", "");
                                                                    if (_mode_target[_mode_count] != this.client.nick && curchan.aov && curchan.aov.indexOf(_this_target) >= 0 && this.client.opmode) {
                                                                        curchan.aov.splice(curchan.aov.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) this.client.isvoice = false;
                                                                    break;
                                                                case 'h':
                                                                    _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c] ? curchan.userhosts[c] : "*@*");
                                                                    curchan.names[c] = curchan.names[c].replace("%", "");
                                                                    if (_mode_target[_mode_count] != this.client.nick && curchan.aoh && curchan.aoh.indexOf(_this_target) >= 0 && this.client.opmode) {
                                                                        curchan.aoh.splice(curchan.aoh.indexOf(_this_target), 1);
                                                                    }
                                                                    if (_mode_target[_mode_count] == this.client.nick) this.client.ishop = false;
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
                            this.client.motd = '';
                            break;
                        case '372': // RPL_MOTD
                            this.client.motd += lines[n] + "\n";
                            //this.client.motd='';
                            break;
                        case '376': // RPL_ENDOFMOTD
                            this.client.motd += lines[n] + "\n";
                            //this.client.motd='';
                            break;
                        case '396': // RPL_HOSTHIDDEN
                            if(data[3])
                                this.client.vhost = data[3];
                            break;
                        case 'JOIN':
                            // <- @msgid=pHZAZJUGTgmdLbzMnFYZ5l-xBZH2fjfPCVLEsLqwDqtsA;time=2022-07-19T17:21:44.038Z :nick!ident@host JOIN #channel * :<realname>
                            _temp = (this.client.messagetags ? data[1].substr(1).split("!") : data[0].substr(1).split("!"));
                            _datatemp = (this.client.messagetags ? 3 : 2);
                            _nick = _temp[0];
                            if (_temp[1])
                                _userhost = _temp[1];
                            if (_temp[1] && this.client.nick == _nick) {
                                this.client.ircuser = _temp[1].split("@")[0];
                            }
                            _channels = data[_datatemp].substr(0).trim().split(",");
                            if (data[_datatemp].indexOf(":") != -1)
                                _channels = data[_datatemp].substr(1).trim().split(",");
                            /*
                            //console.log("debug channels: %s - nick: %s - ircuser: %s - userhost: %s", _channels, _nick, this.client.ircuser, _userhost);
                            //process.exit(1);
                            */
                            for (let x = 0; x < _channels.length; x++) {
                                _channel = _channels[x];
                                __channel = _channel.toLowerCase();
                                if (_nick == this.client.nick) {
                                    if (!this.client.channels[__channel]) {
                                        //console.error("Log Join "+this.client.messagetags+" :", lines[n]);
                                        this.client.channels[__channel] = {
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
                                    else if (this.client.channels[__channel]) {
                                        // Appears to never be executed
                                        this.client.channels[__channel].name = _channel;
                                    }
                                    //this.client.write(`MODE ${_channel}\n`);
                                }
                                else {
                                    if (this.client.channels[__channel]) {
                                        this.client.channels[__channel].name = _channel;
                                        this.client.channels[__channel].names.push(_nick);
                                        this.client.channels[__channel].userhosts.push(_userhost ? _userhost : "*@*");
                                        if (this.client.channels[__channel].isop && this.client.channels[__channel].aop && this.client.channels[__channel].aop.indexOf(_nick + "!" + _userhost) >= 0 && this.client.opmode) {
                                            this.client.write(`MODE ${this.client.channels[__channel].name} +o ${_nick}\n`);
                                        }
                                        if ((this.client.channels[__channel].isop || this.client.channels[__channel].ishop) && this.client.channels[__channel].aoh && this.client.channels[__channel].aoh.indexOf(_nick + "!" + _userhost) >= 0 && this.client.opmode) {
                                            this.client.write(`MODE ${this.client.channels[__channel].name} +h ${_nick}\n`);
                                        }
                                        if ((this.client.channels[__channel].isop || this.client.channels[__channel].ishop) && this.client.channels[__channel].aov && this.client.channels[__channel].aov.indexOf(_nick + "!" + _userhost) >= 0 && this.client.opmode) {
                                            this.client.write(`MODE ${this.client.channels[__channel].name} +v ${_nick}\n`);
                                        }
                                    }
                                }
                            }
                            break;
                        case 'TOPIC':
                            _target = data[2].toLowerCase().trim();
                            _topic = lines[n].substr(lines[n].substr(1).indexOf(":") + 2).trim();
                            if (this.client.channels[_target]) {
                                this.client.channels[_target].topic = _topic;
                                this.client.channels[_target].topic_set = data[0].substr(1).split("!")[0];
                                this.client.channels[_target].topic_time = Math.floor(new Date() / 1000);
                            }
                            break;
                        case '332': // RPL_TOPIC
                            _target = data[3].toLowerCase().trim();
                            _topic = lines[n].substr(lines[n].substr(1).indexOf(":") + 2).trim();
                            if (!this.client.channels[_target])
                                this.client.channels[_target] = {};
                            this.client.channels[_target].topic = _topic;
                            break;
                        case '333': // RPL_TOPICWHOTIME
                            _channel = data[3].toLowerCase().trim();
                            _setter = data[4].split("!")[0].trim();
                            _time = data[5].trim();
                            if (!this.client.channels[_channel])
                                this.client.channels[_channel] = {};
                            this.client.channels[_channel].topic_set = _setter;
                            this.client.channels[_channel].topic_time = _time;
                            break;
                        case 'KICK':
                            _target = (this.client.messagetags ? data[4].trim() : data[3].trim());
                            _channel = (this.client.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
                            if (_target == this.client.nick) {
                                delete this.client.channels[_channel];
                            }
                            else if (this.client.channels[_channel]) {
                                for (let x = 0; x < this.client.channels[_channel].names.length; x++) {
                                    if (this.client.channels[_channel].names[x].replace(/(&|~|@|%|\+)/, "") == _target)
                                        break;
                                    this.client.channels[_channel].names.splice(x, 1);
                                }
                            }
                            break;
                        case 'PART':
                            _target = (this.client.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
                            _sender = (this.client.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
                            if (_sender == this.client.nick) {
                                delete this.client.channels[_target];
                            }
                            else if (this.client.channels[_target]) {
                                for (let x = 0; x < this.client.channels[_target].names.length; x++) {
                                    if (this.client.channels[_target].names[x].replace(/(&|~|@|%|\+)/, "") == _sender)
                                        break;
                                    this.client.channels[_target].names.splice(x, 1);
                                    this.client.channels[_target].userhosts.splice(x, 1);
                                }
                            }
                            break;
                        case 'QUIT':
                            _sender = (this.client.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
                            for (let key in this.client.channels) {
                                if (Object.prototype.hasOwnProperty.call(this.client.channels, key)) {
                                    for (let x = 0; x < this.client.channels[key].names.length; x++) {
                                        if (this.client.channels[key].names[x].replace(/(&|~|@|%|\+)/, "") == _sender) {
                                            this.client.channels[key].names.splice(x, 1);
                                            this.client.channels[key].userhosts.splice(x, 1);
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        case '353': // RPL_NAMEREPLY
                            _channel = data[4].toLowerCase().trim();
                            _names = lines[n].substr(1).split(" :")[1].trim().split(" ");
                            if (!this.client.channels[_channel])
                                break;
                            if (!this.client._getnames[_channel]) {
                                this.client._getnames[_channel] = true;
                                if (!this.client.channels[_channel]) {
                                    this.client.channels[_channel] = {};
                                }
                                this.client.channels[_channel].names = [];
                            }
                            for (let x = 0; x < _names.length; x++) {
                                if (!this.client.channels[_channel])
                                    break;
                                this.client.channels[_channel].names.push(_names[x].trim().split("!")[0]);

                                if (typeof this.client.channels[_channel].userhosts === 'undefined')
                                    this.client.channels[_channel].userhosts = [];

                                if (_names[x].trim().indexOf("!") >= 0)
                                    this.client.channels[_channel].userhosts.push(_names[x].trim().split("!")[1]);
                                /*else
                                  this.client.channels[_channel].userhosts.push("*@*");	*/
                            }
                            break;
                        case '366': // RPL_ENDOFBANLIST
                            _channel = data[3].toLowerCase().trim();
                            this.client._getnames[_channel] = false;
                            break;
                        case 'NICK':
                            _sender = data[1].substr(1).split("!")[0];
                            _new = data[3].substr(1).trim();

                            if (_sender == this.client.nick) {
                                this.client.nick = _new;
                            }

                            for (let key in this.client.channels) {
                                if (Object.prototype.hasOwnProperty.call(this.client.channels, key)) {
                                    for (let x = 0; x < this.client.channels[key].names.length; x++) {
                                        if (this.client.channels[key].names[x].replace(/(&|~|@|%|\+)/, "") == _sender) {
                                            _statut = (/^(&|~|@|%|\+)/.test(this.client.channels[key].names[x].substr(0, 1)) ? this.client.channels[key].names[x].substr(0, 1) : "");
                                            this.client.channels[key].names.splice(x, 1);
                                            this.client.channels[key].names.push(_statut + _new);
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        case '433': // ERR_NICKNAMEINUSE
                            if (this.client.parents.length == 0) {
                                if (data[2] == '*') {
                                    if (global.IRC_STANDARDS) {
                                        this.write("NICK "+data[3].trim()+"_"+"\n");
                                        this.nick=data[3].trim()+"_";
                                    } else {
                                        if (global.DEBUG)
                                            console.log("ERROR 433 is detected. Quit ?");
                                        this.client.end();
                                    }
                                }
                            } else {
                                if (global.DEBUG)
                                    console.log("ERROR 433 !this.client.parents.length is detected. Quit ?");
                                    try {
                                        this.connections[this.client.hash].end();
                                    } catch (e) { }
                                    delete this.connections[this.client.hash];
                            }
                            break;
                        case '451': // ERR_NOTREGISTERED
                            if (this.client.parents.length == 0) {
                                if (data[2] == '*') {
                                    if (global.IRC_STANDARDS) {
                                        this.write("NICK "+data[3].trim()+"_"+"\n");
                                        this.nick=data[3].trim()+"_";
                                    } else {
                                        if (global.DEBUG)
                                            console.log("ERROR 451 is detected. Quit ?");
                                        this.client.end();
                                    }
                                }
                            } else {
                                if (global.DEBUG)
                                    console.log("ERROR 451 !this.client.parents.length is detected. Quit ?");
                                    try {
                                        this.connections[this.client.hash].end();
                                    } catch (e) { }
                                    delete this.connections[this.client.hash];
                            }
                            break;
                    }
                    if (data[1] == "PING") {
                        this.client.write("PONG " + data[2].substr(1).trim() + "\n");
                        continue;
                    }
                    if (data[0] == "PING") {
                        this.client.write("PONG " + data[1].substr(1).trim() + "\n");
                        continue;
                    }
                    if (data[0] == "ERROR") {
                        /*if (this.client.gone) {
                            clearTimeout(this.client.gone);
                            this.client.gone = '';
                            this.client.goneTime = '';
                        }*/
                        try {
                            this.connections[this.client.hash].end();
                        } catch (e) { }
                        delete this.connections[this.client.hash];
                    }
                    if (lines[n].length > 1) {
                        for (let m = 0; m < this.client.parents.length; m++) {
                            this.client.parents[m].write(lines[n] + "\n");
                        }
                    }

                    // Check the last 400 messages that will be sent on the irc web client to sort the new messages
                    if (global.MSG_REDISTRIBUTION && this.client.messagetags && lines[n].startsWith("@")) {


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
                            for (let key in this.client.buffers) {
                                if (Object.prototype.hasOwnProperty.call(this.client.buffers, key)) {
                                    let _n = lines[n].split(" ")[3]; // PRIVMSG <hereTarget> :... - Channel name or PV name

                                    let message = lines[n];
                                    let atIndex1 = message.indexOf(" :");
                                    let atIndex2 = message.indexOf("!");
                                    let source = message.substring(atIndex1 + 2, atIndex2);
                                    let count = 0;

                                    for (let x = 0; x < this.client.buffers[key].privmsgnotice.length; x++) {
                                        if (this.client.buffers[key].privmsgnotice[x].target === _n) {
                                            count++;

                                            if (count >= 300) {
                                                this.client.buffers[key].privmsgnotice.splice(x, 1);
                                                break;
                                            }
                                        }
                                    }

                                    // Adding all messages
                                    this.client.buffers[key].privmsgnotice.push({
                                        source: source,
                                        target: _n,
                                        line: lines[n] + "\n"
                                    });
                                }
                            }
                        }
                        else if (lines[n].split(" ")[2] && global.ircCommandRedistributeMessagesOnConnect.has(lines[n].split(" ")[2].trimEnd())) {
                            if (lines[n].split(" ")[1].substr(1).split("!")[0] == this.client.nick) {
                                continue;
                            }
                            for (let key in this.client.buffers) {
                                if (Object.prototype.hasOwnProperty.call(this.client.buffers, key)) {
                                    let _n = "server.irc";
                                    let count = 0;

                                    for (let x = 0; x < this.client.buffers[key].privmsgnotice.length; x++) {
                                        if (this.client.buffers[key].privmsgnotice[x].target === _n) {
                                            count++;

                                            if (count >= 300) {
                                                this.client.buffers[key].privmsgnotice.splice(x, 1);
                                                break;
                                            }
                                        }
                                    }

                                    // Adding all messages
                                    this.client.buffers[key].privmsgnotice.push({
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
                        for (let key in this.client.buffers) {
                            if (Object.prototype.hasOwnProperty.call(this.client.buffers, key)) {
                                if (!this.client.buffers[key].connected) {
                                    this.client.buffers[key].data += lines[n] + "\n";

                                    // Temporary: replace this system with "PRIVMSG_LINEMAX" ...
                                    let _split = this.client.buffers[key].data.split("\n");
                                    if (_split.length >= global.BUFFER_LINEMAX && global.BUFFER_LINEMAX != 0) {
                                        _split.splice(0, _split.length - global.BUFFER_LINEMAX);
                                        let _line = "";
                                        for (let t = 0; t < _split.length; t++) {
                                            _line += _split[t] + "\n";
                                        }
                                        this.client.buffers[key].data = _line;
                                    }
                                }
                            }
                        }
                    }
                }



            });
            this.client.on('close', () => {
                for (let x = 0; x < this.client.parents.length; x++) {
                    clearInterval(this.client.parents[x].pings);
                    this.client.parents[x].write(":" + this.client.nick + " QUIT :QUIT");
                    this.client.parents[x].end();
                }
                this.client.buffers = false;
                delete this.connections[hash(this.client.nick + this.client.password + this.client.server + this.client.port.toString())];
                this.client.destroy();
            });
            this.client.on('error', () => {
                this.client.end();
            });
            this.client.on('end', () => {
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
