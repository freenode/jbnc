// Bouncer Server
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const crypto = require("crypto");

const ClientConnect = require('../lib/ClientConnect');
const ClientReconnect = require('../lib/ClientReconnect');
const Connections = require('../lib/Connections');

class Server {
    constructor() {
        this.config = global.config;
        this.server = null;
        this.doServer = null;
        this.users = 0;
        this.tlsOptions = null;
        this.instanceConnections = new Connections();
        this.connections = this.instanceConnections.connections;
        this.init();
        //this.listen();
    }

    init() {
        if (global.BOUNCER_PORT.toString().substr(0, 1) == '+') {
            this.tlsOptions = {
                key: fs.readFileSync(global.SERVER_TLS_KEY),
                cert: fs.readFileSync(global.SERVER_TLS_CERT)
            };
            global.BOUNCER_PORT = global.BOUNCER_PORT.substr(1);
            this.doServer = tls.createServer;
        }
        else {
            this.tlsOptions = {};
            this.doServer = net.createServer;
        }

        if (global.DEBUG)
            console.log("Server init() :" + global.SERVER);

        this.server = this.createServer(this.tlsOptions);
    }

    createServer(tlsOptions) {

        if (global.DEBUG)
            console.log("createServer()");

        return this.doServer(tlsOptions, (socket) => {

            if (global.DEBUG)
                console.log("Server doServer()");

            // Used for auth
            socket.badauth = false;
            socket.irc = {};

            // Track connection type
            socket.connected = false;

            // Connection ID
            socket.hash = '';

            // Miscellaneous
            socket.clientbuffer = 'default';
            socket.admin = false;  // Is user an admin
            socket.host = null;
            this.users++;

            // Temp Buffer
            socket._buffer = '';
            socket._outbuffer = ''; // Just used at the beginning only
            socket.hostonce = '';

            // Shack
            socket.lastping = '';
            socket.pings = setInterval(function () {
                if (socket.lastping.length > 0) {
                    socket.end();
                }
                socket.lastping = Date.now() + ".jbnc";
                if (socket.writable)
                    socket.write("PING :" + socket.lastping + "\n");
                else {
                    clearInterval(socket.pings);
                    socket.end();
                }
                if (global.DEBUG) {
                    console.log("PING :" + socket.lastping + "\n");
                }
            }, global.BOUNCER_SHACK * 1000, socket);

            socket.on('data', (chunk) => {
                let _chunk = chunk.toString();
                let lines = _chunk.toString().split('\n');
                if (_chunk.substr(_chunk.length - 1) != '\n') {
                    socket._buffer = lines[0].trim() + "\n";
                }

                if (true) {
                    let input = (socket._buffer + _chunk.trim());
                    if (socket.connected && !socket.badauth && (this.connections[socket.hash] && this.connections[socket.hash].authenticated) && socket._outbuffer.length > 0) {
                        input = socket._outbuffer + input;
                        socket._outbuffer = '';
                    }
                    input = input.split("\n");
                    socket._buffer = '';
                    for (let i = 0; i < input.length; i++) {
                        if (global.DEBUG)
                            console.log("<" + input[i]);
                        let commands = input[i].split(" ");
                        let command = commands[0].toUpperCase();
                        if (!socket.connected && !socket.badauth) {
                            switch (command) {
                                case 'PROXY':
                                    if (global.SERVER_WEBIRCPROXY) {
                                        if (commands[5] && !socket.irc.password) {
                                            socket.host = commands[2];
                                        }
                                    }
                                    else {
                                        socket.hostonce = commands[2];
                                    }
                                    break;
                                case 'WEBIRC':
                                    if (commands[4]) {
                                        if (global.INGRESSWEBIRC.length > 0 && commands[1] == global.INGRESSWEBIRC) {
                                            socket.host = commands[4];
                                        }
                                    }
                                    break;
                                case 'PASS':
                                    if (commands[1]) {
                                        if (global.BOUNCER_PASSWORD.length > 0 && commands[1].split("||")[0] != global.BOUNCER_PASSWORD) {
                                            socket.write(":*jbnc NOTICE * :*** Incorrect Password ***\n");
                                            socket.badauth = true;
                                            socket.end();
                                        }
                                        else {
                                            socket.irc.server = global.SERVER;
                                            socket.irc.port = global.SERVER_PORT;
                                            socket.irc.nick = null;
                                            socket.irc.user = null;
                                            socket.irc.password = null;
                                            socket.irc.realname = null;
                                            socket.irc.serverpassword = null;
                                            socket.irc.nickpassword = null;
                                            socket.irc.accountsasl = null;

                                            const passIrc = input[i].split(' ').splice(1).join(' ').trim();

                                            if (/(.*)\|\|(.*)\/(.*)\|\|(.*)\/(.*)\/(.*)/g.test(passIrc)) {
                                                // Parse the input
                                                const [, , ircPassword, serverInfo, serverPassword, buffer, accountsasl] = passIrc.match(/(.*)\|\|(.*)\/(.*)\|\|(.*)\/(.*)\/(.*)/);

                                                /*console.log("if", "2");
                                                console.log("ircPassword", ircPassword);
                                                console.log("serverInfo", serverInfo);
                                                console.log("serverPassword", serverPassword);
                                                console.log("buffer", buffer);
                                                console.log("accountsasl", accountsasl || "Not provided");
                                                process.exit(1);*/
                                                // Set the password
                                                socket.irc.password = ircPassword;

                                                // Check password length
                                                if (socket.irc.password.replace(/\s/g, '#').length < 6) {
                                                    socket.write(":*jbnc NOTICE * :*** Password too short (min length 6) ***\n");
                                                    socket.badauth = true;
                                                    socket.end();
                                                }

                                                // Hash the password
                                                socket.irc.password = hash(socket.irc.password);

                                                if (global.BOUNCER_MODE === "gateway") {
                                                    if (serverInfo) {
                                                        socket.clientbuffer = serverInfo.trim() + "||" + serverPassword.trim();
                                                    } else {
                                                        socket.end();
                                                    }
                                                } else {
                                                    if (serverInfo || serverPassword || buffer) {
                                                        const [_server, _port] = serverInfo.split(':');
                                                        socket.irc.server = _server || null;
                                                        socket.irc.port = _port ? _port.trim() : null;
                                                        socket.irc.serverpassword = serverPassword || null;
                                                        socket.irc.nickpassword = ircPassword || null;
                                                        socket.clientbuffer = buffer || null;
                                                        socket.irc.accountsasl = accountsasl || null;
                                                    } else {
                                                        socket.end();
                                                    }
                                                }
                                            }
                                            else if (/(.*)\|\|(.*)\/(.*)\|\|(.*)\/(.*)/g.test(passIrc)) {
                                                // Parse the input
                                                const [, , ircPassword, serverInfo, serverPassword, buffer] = passIrc.match(/(.*)\|\|(.*)\/(.*)\|\|(.*)\/(.*)/);

                                                /*console.log("if", "1");
                                                console.log("ircPassword", ircPassword);
                                                console.log("serverInfo", serverInfo);
                                                console.log("serverPassword", serverPassword);
                                                console.log("buffer", buffer);
                                                process.exit(1);*/
                                                // Set the password
                                                socket.irc.password = ircPassword;

                                                // Check password length
                                                if (socket.irc.password.replace(/\s/g, '#').length < 6) {
                                                    socket.write(":*jbnc NOTICE * :*** Password too short (min length 6) ***\n");
                                                    socket.badauth = true;
                                                    socket.end();
                                                }

                                                // Hash the password
                                                socket.irc.password = hash(socket.irc.password);

                                                if (global.BOUNCER_MODE === "gateway") {
                                                    if (serverInfo) {
                                                        socket.clientbuffer = serverInfo.trim() + "||" + serverPassword.trim();
                                                    } else {
                                                        socket.end();
                                                    }
                                                } else {
                                                    if (serverInfo || serverPassword || buffer) {
                                                        const [_server, _port] = serverInfo.split(':');
                                                        socket.irc.server = _server || null;
                                                        socket.irc.port = _port ? _port.trim() : null;
                                                        socket.irc.serverpassword = serverPassword || null;
                                                        socket.irc.nickpassword = ircPassword || null;
                                                        socket.clientbuffer = buffer || null;
                                                        socket.irc.accountsasl = null;
                                                    } else {
                                                        socket.end();
                                                    }
                                                }
                                            }
                                            else {
                                                // Old system
                                                origin = commands[1].trim().split("/");

                                                if (origin[0].indexOf("||") > 0)
                                                    socket.irc.password = origin[0].split("||")[1];
                                                else
                                                    socket.irc.password = origin[0];

                                                if (socket.irc.password.length < 6) {
                                                    socket.write(":*jbnc NOTICE * :*** Password too short (min length 6) ***\n");
                                                    socket.badauth = true;
                                                    socket.end();
                                                }
                                                // hash password
                                                socket.irc.password = hash(socket.irc.password);
                                                if (global.BOUNCER_MODE == "gateway") {
                                                    if (origin.length != 1 && origin.length != 2)
                                                        socket.end();
                                                    else {
                                                        if (origin[1])
                                                            socket.clientbuffer = origin[1].trim();
                                                    }
                                                }
                                                else {
                                                    if (origin.length != 2 && origin.length != 3 && origin.length != 4)
                                                        socket.end();
                                                    else {
                                                        _server_pass = origin[1].split("||");
                                                        _server = _server_pass[0].split(":");
                                                        socket.irc.server = _server[0];
                                                        socket.irc.port = (_server[1] ? _server[1].trim() : 6667);
                                                        if (origin[1].split("||")[1]) {
                                                            socket.irc.serverpassword = origin[1].split("||")[1];
                                                        }
                                                        if (origin[0].split("||")[1]) {
                                                            socket.irc.nickpassword = origin[0].split("||")[1];
                                                        }
                                                        if (origin[2])
                                                            socket.clientbuffer = origin[2].trim();
                                                        if (origin[3])
                                                            socket.irc.accountsasl = origin[3].trim();
                                                    }
                                                }

                                            }
                                        }
                                    }
                                    else {
                                        socket.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                                        socket.badauth = true;
                                        socket.end();
                                    }
                                    break;
                                case 'NICK':
                                    if (!socket.irc.password) {
                                        socket.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                                        socket.badauth = true;
                                        socket.end();
                                    }
                                    else if (commands[1]) {
                                        socket.irc.nick = commands[1].trim();
                                        if (socket.irc.user) {
                                            socket.hash = hash(socket.irc.nick + socket.irc.password + socket.irc.server + socket.irc.port.toString());
                                            if (this.connections[socket.hash]) {
                                                this.clientReconnect(socket);
                                            }
                                            else {
                                                this.clientConnect(socket);
                                            }
                                        }
                                    }
                                    break;
                                case 'USER':
                                    if (!socket.irc.password) {
                                        socket.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                                        socket.badauth = true;
                                        socket.end();
                                    }
                                    else if (commands.length >= 5) {
                                        socket.irc.user = commands[1].trim();
                                        socket.irc.realname = commands.slice(4).join(" ");
                                        if (socket.irc.realname.substr(0, 1) == ':')
                                            socket.irc.realname = socket.irc.realname.substr(1);
                                        if (global.BOUNCER_USER.length > 0 && socket.irc.user != global.BOUNCER_USER) {
                                            socket.write(":*jbnc NOTICE * :*** Incorrect Username ***\n");
                                            socket.end();
                                        }
                                        else {
                                            if (socket.irc.nick) {
                                                socket.hash = hash(socket.irc.nick + socket.irc.password + socket.irc.server + socket.irc.port.toString());
                                                if (this.connections[socket.hash]) {
                                                    this.clientReconnect(socket);
                                                }
                                                else {
                                                    this.clientConnect(socket);
                                                    if (global.DEBUG)
                                                        console.log("Connecting to " + socket.irc.server + ":" + socket.irc.port);
                                                }
                                            }
                                        }
                                    }
                                    else {
                                        socket.write(":*jbnc NOTICE * :*** Your IRC client is faulty. ***\n");
                                        socket.badauth = true;
                                        socket.end();
                                    }
                                    break;
                                case 'CAP': // not RFC1459 Compliant - breaks clients
                                    break;
                                default:
                                    break;
                            }
                        }
                        else if (socket.connected && !socket.badauth) {
                            command = input[i].toString().split(" ");
                            switch (command[0].toUpperCase().trim()) {
                                case 'PONG':
                                    if (command[1]) {
                                        if (command[1].substr(0, 1) == ':')
                                            command[1] = command[1].substr(1);
                                        if (socket.lastping == command[1]) {
                                            socket.lastping = '';
                                        }
                                        else if (socket.hash && this.connections[socket.hash]) {
                                            this.connections[socket.hash].write("PONG " + command[1] + "\n");
                                        }
                                    }
                                    break;
                                case 'QUIT':
                                    socket.end();
                                    break;
                                case 'MONITOR':
                                    if (socket.hash && this.connections[socket.hash]) {
                                        if (command[1] == "+") {
                                            if (!this.connections[socket.hash].ircv3Monitor)
                                                this.connections[socket.hash].ircv3Monitor = true;
                                            this.connections[socket.hash].write("MONITOR + " + command.slice(2).toString() + "\n");
                                        }
                                        else if (command[1] == "-") {
                                            this.connections[socket.hash].write("MONITOR - " + command.slice(2).toString() + "\n");
                                        }
                                        else {
                                            this.connections[socket.hash].write("MONITOR " + command.slice(1).toString() + "\n");
                                        }
                                    }
                                    break;
                                case 'CAP':
                                    socket.write(":*jbnc NOTICE * :*** No CAPabilities available. ***\n");
                                    continue;
                                case 'NICK':
                                    if (socket.hash && this.connections[socket.hash] && command[1]) {
                                        this.connections[socket.hash].write("NICK " + command[1] + "\n");
                                        this.connections[socket.hash].nick = command[1];
                                    }
                                    break;
                                case 'JBNC':
                                    if (!command[1]) {
                                        socket.write(":*jbnc NOTICE * :Welcome to JBNC\n");
                                        socket.write(":*jbnc NOTICE * :***************\n");
                                        socket.write(":*jbnc NOTICE * :Type /JBNC <COMMAND>\n");
                                        socket.write(":*jbnc NOTICE * :Commands:\n");
                                        socket.write(":*jbnc NOTICE * :QUIT - Disconnects and deletes your profile\n");
                                        socket.write(":*jbnc NOTICE * :PASS - Change your password\n");
                                        socket.write(":*jbnc NOTICE * :CONN - Show which devices are connected to your bouncer user connection\n");
                                        socket.write(":*jbnc NOTICE * :BUFFERS - Show what buffers exist and their size\n");
                                        socket.write(":*jbnc NOTICE * :OPMODE - Enable or disable auto-op/hop/voice\n");
                                        socket.write(":*jbnc NOTICE * :CHANNELS - List all active channels\n");
                                        socket.write(":*jbnc NOTICE * :USERHOSTS - List current state of userhosts\n");
                                        if (!socket.admin)
                                            socket.write(":*jbnc NOTICE * :ADMIN - Get admin access\n");
                                        else {
                                            socket.write(":*jbnc NOTICE * :STATS - Get user and connection count\n");
                                            socket.write(":*jbnc NOTICE * :LOAD - Get system Load Information\n");
                                            socket.write(":*jbnc NOTICE * :WHOIS - Get info on a user\n");
                                            socket.write(":*jbnc NOTICE * :KILL - Disconnect a user\n");
                                            socket.write(":*jbnc NOTICE * :WHO - List all connected IRCs\n");
                                        }
                                        socket.write(":*jbnc NOTICE * :***************\n");
                                    }
                                    else {
                                        switch (command[1].toUpperCase().trim()) {
                                            case 'DEBUGCONNECTIONS':
                                                console.log("connections: ", this.connections);
                                                break;
                                            case 'CHANNELS':
                                                socket.write(`:*jbnc NOTICE * :You are currently connected to ${this.instanceConnections.userChannelCount(socket.hash)} channels.\n`);
                                                let Channels = this.instanceConnections.userChannels(socket.hash);
                                                for (let i = 0; i < Channels.length; i++) {
                                                    socket.write(`:*jbnc NOTICE * :Active channel: ${Channels[i]}\n`);
                                                }
                                                socket.write(":*jbnc NOTICE * :End of active channels\n");
                                                break;
                                            case 'USERHOSTS':
                                                for (let key in this.connections[socket.hash].channels) {
                                                    if (this.connections[socket.hash].channels.hasOwnProperty(key)) {
                                                        for (let x = 0; x < this.connections[socket.hash].channels[key].userhosts.length; x++)
                                                            socket.write(":*jbnc NOTICE * :" + x + ") " + this.connections[socket.hash].channels[key].userhosts[x] + " (" + this.connections[socket.hash].channels[key].names[x] + ")\n");
                                                    }
                                                }
                                                socket.write(":*jbnc NOTICE * :End of active userhosts\n");
                                                break;
                                            case 'OPMODE':
                                                if (command[2]) {
                                                    if (command[2].toLowerCase().trim() == "on") {
                                                        this.connections[socket.hash].opmode = true;
                                                    }
                                                    else if (command[2].toLowerCase().trim() == "off") {
                                                        this.connections[socket.hash].opmode = false;
                                                    }
                                                    else
                                                        socket.write(":*jbnc NOTICE * :Valid options are ON|OFF\n");
                                                }
                                                socket.write(":*jbnc NOTICE * :OPMODE is currently " + (this.connections[socket.hash].opmode ? "ON" : "OFF") + "\n");
                                                break;
                                            case 'STATS':
                                                if (socket.admin) {
                                                    socket.write(":*jbnc NOTICE * :" + Object.keys(this.connections).length + " IRC Connections\n");
                                                    socket.write(":*jbnc NOTICE * :" + this.users + " connected devices\n");
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                                                }
                                                break;
                                            case 'LOAD':
                                                if (socket.admin) {
                                                    socket.write(":*jbnc NOTICE * :" + fs.readFileSync("/proc/loadavg") + "\n");
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                                                }
                                                break;
                                            case 'KILL':
                                                if (socket.admin) {
                                                    if (command[2]) {
                                                        if (this.connections[command[2]]) {
                                                            key = command[2];
                                                            socket.write(":*jbnc NOTICE * :" + this.connections[key].nick_original + "!" + this.connections[key].user + "@" + this.connections[key].server + " has been disconnected\n");
                                                            this.connections[key].end();
                                                        }
                                                        else {
                                                            socket.write(":*jbnc NOTICE * :No connection found by that hash.\n");
                                                        }
                                                    }
                                                    else {
                                                        socket.write(":*jbnc NOTICE * :Syntax error\n");
                                                        socket.write(":*jbnc NOTICE * :KILL <user hash>\n");
                                                    }
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                                                }
                                                break;
                                            case 'WHO':
                                                if (socket.admin) {
                                                    socket.write(":*jbnc NOTICE * :Listing " + Object.keys(this.connections).length + " users...\n");
                                                    for (let key in this.connections) {
                                                        if (this.connections.hasOwnProperty(key)) {
                                                            socket.write(":*jbnc NOTICE * :" + this.connections[key].nick_original + "!" + this.connections[key].user + "@" + this.connections[key].server + " (" + key + ")\n");
                                                        }
                                                    }
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                                                }
                                                break;
                                            case 'CONN':
                                                socket.write(":*jbnc NOTICE * :There are " + this.connections[socket.hash].parents.length + " connections to your bouncer user connection.\n");
                                                for (let x = 0; x < this.connections[socket.hash].parents.length; x++) {
                                                    socket.write(":*jbnc NOTICE * :" + this.connections[socket.hash].parents[x].clientbuffer + " (" + this.connections[socket.hash].parents[x].remoteAddress + ")\n");
                                                }
                                                break;
                                            case 'LOGCLEAR':
                                                if (this.connections[socket.hash] && this.connections[socket.hash].buffers) {
                                                    for (let key in this.connections[socket.hash].buffers) {
                                                        if (this.connections[socket.hash].buffers.hasOwnProperty(key)) {
                                                            if (this.connections[socket.hash].buffers[key] && this.connections[socket.hash].buffers[key].privmsgnotice && this.connections[socket.hash].buffers[key].privmsgnotice.length > 0) {
                                                                this.connections[socket.hash].buffers[key].privmsgnotice.length = 0;
                                                            }
                                                        }
                                                    }
                                                }
                                                break;
                                            case 'TARGETLOGCLEAR':
                                                if (command[2]) {
                                                    if (this.connections[socket.hash] && this.connections[socket.hash].buffers) {
                                                        for (let key in this.connections[socket.hash].buffers) {
                                                            if (this.connections[socket.hash].buffers.hasOwnProperty(key)) {
                                                                if (this.connections[socket.hash].buffers[key] && this.connections[socket.hash].buffers[key].privmsgnotice && this.connections[socket.hash].buffers[key].privmsgnotice.length > 0) {
                                                                    for (let x = this.connections[socket.hash].buffers[key].privmsgnotice.length - 1; x >= 0; x--) {
                                                                        if (this.connections[socket.hash].buffers[key].privmsgnotice[x].source === command[2] && this.connections[socket.hash].buffers[key].privmsgnotice[x].target === this.connections[socket.hash].nick) {
                                                                            this.connections[socket.hash].buffers[key].privmsgnotice.splice(x, 1);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                break;
                                            case 'BUFFERS':
                                                totalbuffers = 0;
                                                for (let key in this.connections[socket.hash].buffers) {
                                                    if (this.connections[socket.hash].buffers.hasOwnProperty(key)) {
                                                        connected = this.connections[socket.hash].buffers[key].connected;
                                                        socket.write(":*jbnc NOTICE * :" + key + " (" + (connected ? "connected" : "not connected") + ") [" + this.connections[socket.hash].buffers[key].data.length + " bytes]\n");
                                                        totalbuffers++;
                                                    }
                                                }
                                                socket.write(":*jbnc NOTICE * :You have " + totalbuffers + " buffers.\n");
                                                break
                                            case 'WHOIS':
                                                if (socket.admin) {
                                                    if (command[2]) {
                                                        if (this.connections[command[2]]) {
                                                            key = command[2];
                                                            socket.write(":*jbnc NOTICE * :" + this.connections[key].nick_original + "!" + this.connections[key].user + "@" + this.connections[key].server + "\n");
                                                            socket.write(":*jbnc NOTICE * :Currently connected with " + this.connections[key].parents.length + " devices\n");
                                                            socket.write(":*jbnc NOTICE * :User is in " + Object.keys(this.connections[key].channels).length + " channels\n");
                                                        }
                                                        else {
                                                            socket.write(":*jbnc NOTICE * :No connection found by that hash.\n");
                                                        }
                                                    }
                                                    else {
                                                        socket.write(":*jbnc NOTICE * :Syntax error\n");
                                                        socket.write(":*jbnc NOTICE * :WHOIS <user hash>\n");
                                                    }
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                                                }
                                                break;
                                            case 'ADMIN':
                                                if (!command[2]) {
                                                    socket.write(":*jbnc NOTICE * :Syntax error\n");
                                                    socket.write(":*jbnc NOTICE * :ADMIN <admin password>\n");
                                                }
                                                else {
                                                    if (command[2] == global.BOUNCER_ADMIN && global.BOUNCER_ADMIN.length > 0) {
                                                        socket.write(":*jbnc NOTICE * :Password Accepted.\n");
                                                        socket.write(":*jbnc NOTICE * :You have been elevated to admin.\n");
                                                        socket.admin = true;
                                                    }
                                                    else {
                                                        socket.write(":*jbnc NOTICE * :Incorrect password..\n");
                                                    }
                                                }
                                                break;
                                            case 'QUIT':
                                                socket.write(":*jbnc NOTICE * :Sayonara.\n");
                                                if (typeof this.connections[socket.hash] !== 'undefined') {
                                                    this.connections[socket.hash].write("QUIT :jbnc gateway\n");
                                                    this.connections[socket.hash].end();
                                                    delete this.connections[socket.hash];
                                                }
                                                break;
                                            case 'PASS':
                                                if (command[3]) {
                                                    if (hash(command[2]) == this.connections[socket.hash].password) {
                                                        this.connections[socket.hash].password = hash(command[3]);
                                                        socket.irc.password = this.connections[socket.hash].password;
                                                        socket.write(":*jbnc NOTICE * :Password changed to " + command[3] + "\n");
                                                        _newhash = hash(socket.irc.nick + socket.irc.password + socket.irc.server + socket.irc.port.toString());
                                                        this.connections[_newhash] = this.connections[socket.hash];
                                                        delete this.connections[socket.hash];
                                                        socket.hash = _newhash;
                                                    }
                                                    else
                                                        socket.write(":*jbnc NOTICE * :Incorrect password.\n");
                                                }
                                                else {
                                                    socket.write(":*jbnc NOTICE * :Syntax error.\n");
                                                    socket.write(":*jbnc NOTICE * :PASS <old password> <new password>.\n");
                                                }
                                                break;
                                            default:
                                                socket.write(":*jbnc NOTICE * :Unknown command.\n");
                                                break;
                                        }
                                        break;
                                    }
                                    break;
                                default:
                                    if (typeof this.connections[socket.hash] === 'undefined')
                                        continue;
                                    // supress joins of channels we are already in because some clients dont react properly.
                                    if (input[i] && this.connections[socket.hash] && input[i].toString().substr(0, 4) == "JOIN") {
                                        command = input[i].toString().trim().split(" ");
                                        if (!command[1])
                                            break;
                                        let channels = command[1].split(",");
                                        if (command[2])
                                            passwords = command[2].split(",");
                                        let l = 0;
                                        for (let m = 0; m < channels.length; m++) {
                                            if (typeof this.connections[socket.hash].channels !== 'undefined' && this.connections[socket.hash].channels[channels[m].trim().toLowerCase()]) {
                                                if (command[2] && l < passwords.length)
                                                    l++;
                                                continue;
                                            }
                                            else {
                                                if (command[2] && l < passwords.length) {
                                                    this.connections[socket.hash].write("JOIN " + channels[m].trim() + " " + passwords[l] + "\n");
                                                    l++;
                                                }
                                                else
                                                    this.connections[socket.hash].write("JOIN " + channels[m].trim() + "\n");
                                            }
                                        }
                                        break;
                                    }
                                    if (input[i] && this.connections[socket.hash] && this.connections[socket.hash].authenticated) {
                                        this.connections[socket.hash].write(input[i].toString() + "\n");
                                        for (let m = 0; m < this.connections[socket.hash].parents.length; m++) {
                                            if (this.connections[socket.hash].parents[m] == socket)
                                                continue;
                                            else if (input[i].toString().split(" ")[0] != "PONG" && input[i].toString().split(" ")[0] != "MODE" && input[i].toString().split(" ")[0] != "JOIN") {
                                                this.connections[socket.hash].parents[m].write(":" + this.connections[socket.hash].nick + " " + input[i].toString() + "\n");
                                            }
                                        }
                                        if (input[i].toString().substr(0, 7) == "PRIVMSG" || input[i].toString().substr(0, 6) == "NOTICE" || input[i].toString().substr(0, 7) == "WALLOPS" || input[i].toString().substr(0, 7) == "GLOBOPS") {
                                            for (let key in this.connections[socket.hash].buffers) {
                                                if (this.connections[socket.hash].buffers.hasOwnProperty(key)) {
                                                    if (!this.connections[socket.hash].buffers[key].connected) {
                                                        this.connections[socket.hash].buffers[key].data += ":" + this.connections[socket.hash].nick + "!" + this.connections[socket.hash].ircuser + "@" + this.connections[socket.hash].host + " " + input[i] + "\n";
                                                        if (this.connections[socket.hash].buffers[key].data.length >= global.BUFFER_MAXSIZE && global.BUFFER_MAXSIZE != 0)
                                                            delete this.connections[socket.hash].buffers[key];
                                                    }
                                                }
                                            }
                                            let count = 0;
                                            for (let key in this.connections[socket.hash].buffers) {
                                                if (this.connections[socket.hash].buffers.hasOwnProperty(key)) {
                                                    count++;
                                                }
                                            }
                                            if (!count) {
                                                this.connections[socket.hash].end();
                                            }
                                        }
                                    }
                                    else {
                                        socket._outbuffer += input[i].toString() + "\n";
                                    }
                                    break;
                            }
                        }
                        else {
                            socket.end();
                        }
                    }
                }
            });
            socket.on('close', () => {
                clearInterval(socket.pings);
                if (this.connections[socket.hash] && this.connections[socket.hash].buffers[socket.clientbuffer]) {
                    this.connections[socket.hash].buffers[socket.clientbuffer].connected = false;
                }
                if (this.connections[socket.hash]) {
                    let i=0;
                    for (let i = 0; i < this.connections[socket.hash].parents.length; i++) {
                        if (this.connections[socket.hash].parents[i] == socket)
                            break;
                    }
                    if (i < this.connections[socket.hash].parents.length) {
                        this.connections[socket.hash].parents.splice(i, 1);
                        if (this.connections[socket.hash].parents.length == 0) {
                            this.connections[socket.hash].connected = false;
                            this.connections[socket.hash].write(`AWAY :away-${Math.floor(Date.now() / 1000)}\n`);
                            if (global.BOUNCER_TIMEOUT != 0 && global.BOUNCER_TIMEOUT != null) {
                                this.connections[socket.hash].gone = setTimeout(() => { try { this.connections[socket.hash].write("QUIT :jbnc gateway\n"); this.connections[socket.hash].end(); } catch (e) { } delete this.connections[socket.hash]; }, global.BOUNCER_TIMEOUT * 1000, socket.hash);
                            }
                        }
                    }
                }
                this.users--;
                socket.destroy();
            });
            socket.on('error', (err) => {
                console.log(err);
                socket.end();
            });

            // Track connection type
            socket.on('end', () => {
                console.log('Connection finished: socket');
                if (this.connections[socket.hash] && this.connections[socket.hash].preConnectionLogout == false) {
                    this.connections[socket.hash].preConnectionLogout = true;
                }
            });
        });
    }

    clientReconnect(socket) {
        return new ClientReconnect(socket, this);
    }

    clientConnect(socket) {
        return new ClientConnect(socket, this);
    }

    listen() {
        if (global.BOUNCER_IP)
            this.server.listen(global.BOUNCER_PORT, global.BOUNCER_IP);
        else
            this.server.listen(global.BOUNCER_PORT);

        if (global.DEBUG)
            console.log("The Bouncer Server is started. listen()");

    }

}


// Helper Functions
function hash(data) {
    return crypto.createHash('sha256').update(data, 'utf8').digest('base64');
}

module.exports = Server;