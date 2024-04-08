// jbnc v0.8
// Copyright (C) 2020 Andrew Lee <andrew@imperialfamily.com>
// All Rights Reserved.
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const crypto = require("crypto");
const dns = require('dns');
const reverse = require('util').promisify(dns.reverse);

// Load jbnc.conf
_config = process.argv[2]?process.argv[2]:"jbnc.conf";
var config = {};
if(fs.existsSync(_config)) {
  config = JSON.parse(fs.readFileSync(_config));
}
else {
  console.error(`No config file found: ${_config}`);
  process.exit(1);
}

// Set config vars
var BOUNCER_PORT = config.bouncerPort?config.bouncerPort:8888;
const BOUNCER_IP = config.bouncerIp?config.bouncerIp:null;
const BOUNCER_USER = config.bouncerUser?config.bouncerUser:'';
var BOUNCER_PASSWORD = config.bouncerPassword?config.bouncerPassword:'';
var BOUNCER_ADMIN = config.bouncerAdmin?config.bouncerAdmin:'';
var BOUNCER_DEFAULT_OPMODE = config.bouncerDefaultOpmode?config.bouncerDefaultOpmode:false;
const BOUNCER_MODE = config.mode?config.mode:'bouncer';
const BOUNCER_TIMEOUT = config.bouncerTimeout?config.bouncerTimeout:0;
const BUFFER_MAXSIZE = config.bufferMaxSize?config.bufferMaxSize:52428800;
const BUFFER_LINEMAX = config.lineMax?config.lineMax:1500;
const BOUNCER_SHACK = config.bouncerShack?config.bouncerShack:10;
const SERVER_WEBIRC = config.webircPassword?config.webircPassword:'';
const SERVER_WEBIRCHASHIP = config.webircHashIp?true:false;
const SERVER_WEBIRCPROXY = config.webircProxy?true:false;
const SERVER_TLS_KEY = config.tlsKey?config.tlsKey:'privkey.pem';
const SERVER_TLS_CERT = config.tlsCert?config.tlsCert:'fullchain.pem';
const SERVER_PORT = BOUNCER_MODE=='gateway'?(config.serverPort?config.serverPort:0):0;
const INGRESSWEBIRC = config.ingresswebircPassword?config.ingresswebircPassword:'';
const SERVER = BOUNCER_MODE=='gateway'?(config.server?config.server:''):'';
const DEBUG = config.debug?config.debug:false;


// Reload passwords on sighup
process.on('SIGHUP',function() {
  if(fs.existsSync(_config)) config = JSON.parse(fs.readFileSync(_config));
  else process.exit(1);

  BOUNCER_PASSWORD=config.bouncerPassword?config.bouncerPassword:'';
  BOUNCER_ADMIN=config.bouncerAdmin?config.bouncerAdmin:'';
});

// Prevent BNC from crashing for all other users when an error is caused by a user (with log error and time)
process.on('uncaughtException', (err, origin) => {
  console.error(`${parseInt(Number(new Date()) / 1000)} # Serious problem (${origin}) - this should not happen but the JBNC is still running. ${err.stack}`);
});


// Track IRC (Server) Connections
var connections={};

// Helper Functions
function hash(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('base64');
}
function iphash(data) {
  return crypto.createHash('md5').update(data).digest('hex').substr(0,6);
}

String.prototype.hexEncode = function(){
  var hex, i;

  var result = "";
  for (i=0; i<this.length; i++) {
      hex = this.charCodeAt(i).toString(16);
      result += ("000"+hex).slice(-4);
  }

  return result
}	   
// Bouncer Server
let server;
let doServer;
let tlsOptions;
if(BOUNCER_PORT.toString().substr(0,1)=='+') {
  tlsOptions = {
    key: fs.readFileSync(SERVER_TLS_KEY),
    cert: fs.readFileSync(SERVER_TLS_CERT)
  };
  BOUNCER_PORT=BOUNCER_PORT.substr(1);
  doServer = tls.createServer;
}
else {
  tlsOptions = {};
  doServer = net.createServer;
}
var users=0;
server = doServer(tlsOptions,function(socket) {
  // Used for auth
  socket.badauth=false;
  socket.irc={};

  // Track connection type
  socket.connected=false;

  // Connection ID
  socket.hash='';

  // Miscellaneous
  socket.clientbuffer='default';
  socket.admin=false;  // Is user an admin
  socket.host=null;
  users++;

  // Temp Buffer
  socket._buffer='';
  socket._outbuffer=''; // Just used at the beginning only
  socket.hostonce='';

  // Shack
  socket.lastping='';
  socket.pings = setInterval(function() {
    if(socket.lastping.length>0) {
      socket.end();
    }
    socket.lastping=Date.now()+".jbnc";
    if(socket.writable)
      socket.write("PING :"+socket.lastping+"\n");
    else {
      clearInterval(socket.pings);
      socket.end();
    }
    if(DEBUG) {
      console.log("PING :"+socket.lastping+"\n");
    }
  },BOUNCER_SHACK*1000,socket);

  socket.on('data', function(chunk) {
    _chunk = chunk.toString();
    let lines = _chunk.toString().split('\n');
    if (_chunk.substr(_chunk.length-1) != '\n') {
        this._buffer = lines[0].trim()+"\n";
    }

    if (true) {
      input = (this._buffer + _chunk.trim());
      if(this.connected && !this.badauth && (connections[this.hash] && connections[this.hash].authenticated) &&this._outbuffer.length>0) {
        input=this._outbuffer+input;
        this._outbuffer='';
      }
      input=input.split("\n");
      this._buffer='';
      for(i=0;i<input.length;i++) {
        if(DEBUG)
          console.log("<" +input[i]);
        let commands=input[i].split(" ");
        let command=commands[0].toUpperCase();
        if(!this.connected && !this.badauth) {
          switch(command) {
            case 'PROXY':
              if(SERVER_WEBIRCPROXY) {
                if(commands[5] && !this.irc.password) {
                  this.host=commands[2];
                }
              }
              else {
                this.hostonce=commands[2];
              }
              break;
            case 'WEBIRC':
              if(commands[4]) {
                if(INGRESSWEBIRC.length>0 && commands[1]==INGRESSWEBIRC) {
                  this.host=commands[4];
                }
              }
              break;
            case 'PASS':
              if(commands[1]) {
                if(BOUNCER_PASSWORD.length>0 && commands[1].split("||")[0]!=BOUNCER_PASSWORD) {
                  this.write(":*jbnc NOTICE * :*** Incorrect Password ***\n");
                  this.badauth=true;
                  this.end();
                }
                else {
                  this.irc.server=SERVER;
                  this.irc.port=SERVER_PORT;
                  this.irc.nick=null;
                  this.irc.user=null;
                  this.irc.password=null;
                  this.irc.realname=null;
                  this.irc.serverpassword=null;
                  this.irc.nickpassword=null;
                  this.irc.accountsasl=null;
                  origin = commands[1].trim().split("/");
                  if(origin[0].indexOf("||")>0)
                    this.irc.password = origin[0].split("||")[1];
                  else
                    this.irc.password = origin[0];

                  if(this.irc.password.length < 6) {
                    this.write(":*jbnc NOTICE * :*** Password too short (min length 6) ***\n");
                    this.badauth=true;
                    this.end();
                  }
                  // hash password
                  this.irc.password = hash(this.irc.password);
                  if(BOUNCER_MODE=="gateway") {
                    if(origin.length!=1 && origin.length!=2)
                      this.end();
                    else {
                      if(origin[1])
                        this.clientbuffer=origin[1].trim();
                    }
                  }
                  else {
                    if(origin.length!=2 && origin.length!=3 && origin.length!=4)
                      this.end();
                    else {
                      _server_pass = origin[1].split("||");
                      _server = _server_pass[0].split(":");
                      this.irc.server = _server[0];
                      this.irc.port = (_server[1] ? _server[1].trim() : 6667);
                      if(origin[1].split("||")[1]) {
                        this.irc.serverpassword=origin[1].split("||")[1];
                      }
                      if(origin[0].split("||")[1]) {
                        this.irc.nickpassword=origin[0].split("||")[1];
                      }							
                      if(origin[2])
                        this.clientbuffer=origin[2].trim();
                      if(origin[3])
                        this.irc.accountsasl=origin[3].trim();
                    }
                  }
                }
              }
              else {
                this.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                this.badauth=true;
                this.end();
              }
              break;
            case 'NICK':
              if(!this.irc.password) {
                this.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                this.badauth=true;
                this.end();
              }
              else if(commands[1]) {
                this.irc.nick=commands[1].trim();
                if(false&&this.irc.user) {
                  this.hash=hash(this.irc.nick+this.irc.user+this.irc.password+this.irc.server+this.irc.port.toString());
                  if(connections[socket.hash]) {
                    clientReconnect(this);
                  }
                  else {
                    clientConnect(this);
                  }
                }
              }
              break;
            case 'USER':
              if(!this.irc.password) {
                this.write(":*jbnc NOTICE * :*** This is a JBNC Server.  You must set a password.\n");
                this.badauth=true;
                this.end();
              }
              else if(commands.length >= 5) {
                this.irc.user = commands[1].trim();
                this.irc.realname = commands.slice(4).join(" ");
                if(this.irc.realname.substr(0,1)==':')
                  this.irc.realname=this.irc.realname.substr(1);
                if(BOUNCER_USER.length>0 && this.irc.user!=BOUNCER_USER) {
                  this.write(":*jbnc NOTICE * :*** Incorrect Username ***\n");
                  this.end();
                }
                else {
                  if(this.irc.nick) {
                    this.hash=hash(this.irc.nick+this.irc.password+this.irc.server+this.irc.port.toString());
                    if(connections[socket.hash]) {
                      clientReconnect(this);
                    }
                    else {
                      clientConnect(this);
                      if(DEBUG)
                        console.log("Connecting to "+this.irc.server+":"+this.irc.port);
                    }
                  }
                }
              }
              else {
                this.write(":*jbnc NOTICE * :*** Your IRC client is faulty. ***\n");
                this.badauth=true;
                this.end();
              }
              break;
            case 'CAP': // not RFC1459 Compliant - breaks clients
              break;
            default:
              break;
          }
        }
        else if(this.connected && !this.badauth) {
          command = input[i].toString().split(" ");
          switch(command[0].toUpperCase().trim()) {
            case 'PONG':
              if(command[1]) {
                if(command[1].substr(0,1)==':')
                  command[1]=command[1].substr(1);
                if(this.lastping == command[1]) {
                  this.lastping='';
                }
                else if(this.hash && connections[this.hash]) {
                  connections[this.hash].write("PONG "+command[1]+"\n");
                }
              }
              break;
            case 'QUIT':
              this.end();
              break;
            case 'MONITOR':
              if(this.hash && connections[this.hash]) {
                if(command[1]=="+"){
                  if(!connections[this.hash].ircv3Monitor)
                    connections[this.hash].ircv3Monitor=true;
                  connections[this.hash].write("MONITOR + "+command.slice(2).toString()+"\n");
                }
                else if(command[1]=="-"){
                  connections[this.hash].write("MONITOR - "+command.slice(2).toString()+"\n");
                }
                else {
                  connections[this.hash].write("MONITOR "+command.slice(1).toString()+"\n");
                }
              }
              break;
            case 'CAP':
              this.write(":*jbnc NOTICE * :*** No CAPabilities available. ***\n");
              continue;
            case 'NICK':
              if(this.hash && connections[this.hash] && command[1]) {
                connections[this.hash].write("NICK "+command[1]+"\n");
                //connections[this.hash].nick=command[1];
              }
              break;
            case 'JBNC':
              if(!command[1]) {
                this.write(":*jbnc NOTICE * :Welcome to JBNC\n");
                this.write(":*jbnc NOTICE * :***************\n");
                this.write(":*jbnc NOTICE * :Type /JBNC <COMMAND>\n");
                this.write(":*jbnc NOTICE * :Commands:\n");
                this.write(":*jbnc NOTICE * :QUIT - Disconnects and deletes your profile\n");
                this.write(":*jbnc NOTICE * :PASS - Change your password\n");
                this.write(":*jbnc NOTICE * :CONN - Show which devices are connected to your bouncer user connection\n");
                this.write(":*jbnc NOTICE * :BUFFERS - Show what buffers exist and their size\n");
                this.write(":*jbnc NOTICE * :OPMODE - Enable or disable auto-op/hop/voice\n");
                this.write(":*jbnc NOTICE * :CHANNELS - List all active channels\n");
                this.write(":*jbnc NOTICE * :USERHOSTS - List current state of userhosts\n");
                if(!this.admin)
                  this.write(":*jbnc NOTICE * :ADMIN - Get admin access\n");
                else {
                  this.write(":*jbnc NOTICE * :STATS - Get user and connection count\n");
                  this.write(":*jbnc NOTICE * :LOAD - Get system Load Information\n");
                  this.write(":*jbnc NOTICE * :WHOIS - Get info on a user\n");
                  this.write(":*jbnc NOTICE * :KILL - Disconnect a user\n");
                  this.write(":*jbnc NOTICE * :WHO - List all connected IRCs\n");
                }
                this.write(":*jbnc NOTICE * :***************\n");
              }
              else {
                switch(command[1].toUpperCase().trim()) {
                  case 'CHANNELS':
                    for (key in connections[this.hash].channels) {
                      if (connections[this.hash].channels.hasOwnProperty(key)) {
                        this.write(":*jbnc NOTICE * :Active channel: "+connections[this.hash].channels[key].name+"\n");
                      }
                    }
                    this.write(":*jbnc NOTICE * :End of active channels\n");
                    break;
                  case 'USERHOSTS':
                    for (key in connections[this.hash].channels) {
                      if (connections[this.hash].channels.hasOwnProperty(key)) {
                        for(x=0;x<connections[this.hash].channels[key].userhosts.length;x++)
                        this.write(":*jbnc NOTICE * :"+x+") "+connections[this.hash].channels[key].userhosts[x]+" ("+connections[this.hash].channels[key].names[x]+")\n");
                      }
                    }
                    this.write(":*jbnc NOTICE * :End of active userhosts\n");
                    break;
                  case 'OPMODE':
                    if(command[2]) {
                      if(command[2].toLowerCase().trim()=="on") {
                        connections[this.hash].opmode=true;
                      }
                      else if(command[2].toLowerCase().trim()=="off") {
                        connections[this.hash].opmode=false;
                      }
                      else
                        this.write(":*jbnc NOTICE * :Valid options are ON|OFF\n");
                    }
                    this.write(":*jbnc NOTICE * :OPMODE is currently "+(connections[this.hash].opmode?"ON":"OFF")+"\n");
                    break;
                  case 'STATS':
                    if(this.admin) {
                      this.write(":*jbnc NOTICE * :"+Object.keys(connections).length+" IRC Connections\n");
                      this.write(":*jbnc NOTICE * :"+users+" connected devices\n");
                    }
                    else {
                      this.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                    }
                    break;
                  case 'LOAD':
                    if(this.admin) {
                      this.write(":*jbnc NOTICE * :"+fs.readFileSync("/proc/loadavg")+"\n");
                    }
                    else {
                      this.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                    }
                    break;
                  case 'KILL':
                    if(this.admin) {
                      if(command[2]) {
                        if(connections[command[2]]) {
                          key=command[2];
                          this.write(":*jbnc NOTICE * :"+connections[key].nick_original+"!"+connections[key].user+"@"+connections[key].server+" has been disconnected\n");
                          connections[key].end();
                        }
                        else {
                          this.write(":*jbnc NOTICE * :No connection found by that hash.\n");
                        }
                      }
                      else {
                        this.write(":*jbnc NOTICE * :Syntax error\n");
                        this.write(":*jbnc NOTICE * :KILL <user hash>\n");
                      }
                    }
                    else {
                      this.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                    }
                    break;
                  case 'WHO':
                    if(this.admin) {
                      this.write(":*jbnc NOTICE * :Listing "+Object.keys(connections).length+" users...\n");
                      for(key in connections) {
                        if(connections.hasOwnProperty(key)) {
                          this.write(":*jbnc NOTICE * :"+connections[key].nick_original+"!"+connections[key].user+"@"+connections[key].server+" ("+key+")\n");
                        }
                      }
                    }
                    else {
                      this.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                    }
                    break;
                  case 'CONN':
                    this.write(":*jbnc NOTICE * :There are "+ connections[this.hash].parents.length +" connections to your bouncer user connection.\n");
                    for(x=0;x<connections[this.hash].parents.length;x++) {
                      this.write(":*jbnc NOTICE * :"+connections[this.hash].parents[x].clientbuffer+" ("+connections[this.hash].parents[x].remoteAddress+")\n");
                    }
                    break;
                  case 'BUFFERS':
                   totalbuffers = 0;
                    for(key in connections[this.hash].buffers) {
                      if(connections[this.hash].buffers.hasOwnProperty(key)) {
                        connected = connections[this.hash].buffers[key].connected;
                        this.write(":*jbnc NOTICE * :"+key+" ("+(connected?"connected":"not connected")+") ["+connections[this.hash].buffers[key].data.length+" bytes]\n");
                        totalbuffers++;
                      }
                    }
                    this.write(":*jbnc NOTICE * :You have " + totalbuffers + " buffers.\n");
                    break
                  case 'WHOIS':
                    if(this.admin) {
                      if(command[2]) {
                        if(connections[command[2]]) {
                          key=command[2];
                          this.write(":*jbnc NOTICE * :"+connections[key].nick_original+"!"+connections[key].user+"@"+connections[key].server+"\n");
                          this.write(":*jbnc NOTICE * :Currently connected with "+connections[key].parents.length+" devices\n");
                          this.write(":*jbnc NOTICE * :User is in "+Object.keys(connections[key].channels).length+" channels\n");
                        }
                        else {
                          this.write(":*jbnc NOTICE * :No connection found by that hash.\n");
                        }
                      }
                      else {
                        this.write(":*jbnc NOTICE * :Syntax error\n");
                        this.write(":*jbnc NOTICE * :WHOIS <user hash>\n");
                      }
                    }
                    else {
                      this.write(":*jbnc NOTICE * :You do not have admin privileges.\n");
                    }
                    break;
                  case 'ADMIN':
                    if(!command[2]) {
                      this.write(":*jbnc NOTICE * :Syntax error\n");
                      this.write(":*jbnc NOTICE * :ADMIN <admin password>\n");
                    }
                    else {
                      if(command[2]==BOUNCER_ADMIN && BOUNCER_ADMIN.length>0) {
                        this.write(":*jbnc NOTICE * :Password Accepted.\n");
                        this.write(":*jbnc NOTICE * :You have been elevated to admin.\n");
                        this.admin=true;
                      }
                      else {
                        this.write(":*jbnc NOTICE * :Incorrect password..\n");
                      }
                    }
                    break;
                  case 'QUIT':
                    this.write(":*jbnc NOTICE * :Sayonara.\n");
                    if (typeof connections[this.hash] !== 'undefined') {
                      connections[this.hash].write("QUIT :jbnc gateway\n");
                      connections[this.hash].end();
                      delete connections[this.hash];
                    }
                    break;
                  case 'PASS':
                    if(command[3]) {
                      if(hash(command[2])==connections[this.hash].password) {
                        connections[this.hash].password=hash(command[3]);
                        this.irc.password=connections[this.hash].password;
                        this.write(":*jbnc NOTICE * :Password changed to "+command[3]+"\n");
                        _newhash=hash(this.irc.nick+this.irc.password+this.irc.server+this.irc.port.toString());
                        connections[_newhash]=connections[this.hash];
                        delete connections[this.hash];
                        this.hash=_newhash;
                      }
                      else
                        this.write(":*jbnc NOTICE * :Incorrect password.\n");
                    }
                    else {
                      this.write(":*jbnc NOTICE * :Syntax error.\n");
                      this.write(":*jbnc NOTICE * :PASS <old password> <new password>.\n");
                    }
                    break;
                  default:
                    this.write(":*jbnc NOTICE * :Unknown command.\n");
                    break;
                }
                break;
              }
              break;
            default:
              /*if(typeof connections[this.hash] === 'undefined' )
              continue;*/
              // supress joins of channels we are already in because some clients dont react properly.
              if(input[i] && connections[this.hash] && input[i].toString().substr(0,4)=="JOIN") {
                command=input[i].toString().trim().split(" ");
                if(!command[1])
                  break;
                channels=command[1].split(",");
                if(command[2])
                  passwords=command[2].split(",");
                l=0;
                for(m=0;m<channels.length;m++) {
                  if(typeof connections[this.hash].channels !== 'undefined' && connections[this.hash].channels[channels[m].trim().toLowerCase()]) {
                    if(command[2] && l<passwords.length)
                      l++;
                    continue;
                  }
                  else {
                    if(command[2] && l<passwords.length) {
                      connections[this.hash].write("JOIN "+channels[m].trim()+" "+passwords[l]+"\n");
                      l++;
                    }
                    else
                      connections[this.hash].write("JOIN "+channels[m].trim()+"\n");
                  }
                }
                break;
              }
              if(input[i] && connections[this.hash] && connections[this.hash].authenticated) {
                connections[this.hash].write(input[i].toString() + "\n");
                for(m=0;m<connections[this.hash].parents.length;m++) {
                  if(connections[this.hash].parents[m]==this)
                    continue;
                  else if(input[i].toString().split(" ")[0]!="PONG" && input[i].toString().split(" ")[0]!="MODE" && input[i].toString().split(" ")[0]!="JOIN") {
                    connections[this.hash].parents[m].write(":"+connections[this.hash].nick+" "+input[i].toString() + "\n");
                  }
                }
                if(input[i].toString().substr(0,7)=="PRIVMSG" || input[i].toString().substr(0,6)=="NOTICE" || input[i].toString().substr(0,7)=="WALLOPS" || input[i].toString().substr(0,7)=="GLOBOPS") {
                  for(key in connections[this.hash].buffers) {
                    if(connections[this.hash].buffers.hasOwnProperty(key)) {
                      if(!connections[this.hash].buffers[key].connected) {
                        connections[this.hash].buffers[key].data+=":"+connections[this.hash].nick+"!"+connections[this.hash].ircuser+"@"+connections[this.hash].host+" "+input[i]+"\n";
                        if(connections[this.hash].buffers[key].data.length>=BUFFER_MAXSIZE && BUFFER_MAXSIZE!=0)
                          delete connections[this.hash].buffers[key];
                      }
                    }
                  }
                  count=0;
                  for(key in connections[this.hash].buffers) {
                    if(connections[this.hash].buffers.hasOwnProperty(key)) {
                      count++;
                    }
                  }
                  if(!count) {
                    connections[this.hash].end();
                  }
                }
              }
              else {
                this._outbuffer+=input[i].toString() + "\n";
              }
              break;
          }
        }
        else {
          this.end();
        }
      }
    }
  });
  socket.on('close', function() {
    clearInterval(this.pings);
    if(connections[this.hash] && connections[this.hash].buffers[this.clientbuffer]) {
      connections[this.hash].buffers[this.clientbuffer].connected=false;
    }
    if(connections[this.hash]) {
      for(i=0;i<connections[this.hash].parents.length;i++) {
        if(connections[this.hash].parents[i]==this)
          break;
      }
      if(i<connections[this.hash].parents.length) {
        connections[this.hash].parents.splice(i,1);
        if(connections[this.hash].parents.length==0) {
          connections[this.hash].connected=false;
          connections[this.hash].write("AWAY :away\n");
          if(BOUNCER_TIMEOUT!=0 && BOUNCER_TIMEOUT!=null) {
            connections[this.hash].gone=setTimeout(()=>{connections[this.hash].end();delete connections[this.hash];},BOUNCER_TIMEOUT*1000,this.hash);
          }
        }
      }
    }
    users--;
    this.destroy();
  });
  socket.on('error', function(err) {
    console.log(err);
    this.end();
  });
});

// IRC Client
function clientReconnect(socket) {
  let _success = true;
  if ( socket.connected ) 
    _success = false;
  if ( _success ) {
    let connection=connections[socket.hash];
    connection.parents[connection.parents.length] = socket;
    clearTimeout(connection.gone);
    socket.connected=true;
    newdevice=false;
    if(!connection.buffers[socket.clientbuffer]) {
      connection.buffers[socket.clientbuffer]={data:'',connected:true};
      newdevice=true;
    }
    else
      connection.buffers[socket.clientbuffer].connected=true;
    socket.write(connection.connectbuf+"\n");
    if(connection.nick!=socket.irc.nick)
      socket.write(":"+connection.nick_original+" NICK "+connection.nick+"\n");
    if(connection.ircv3Monitor)
      connection.write("MONITOR S\n");
    if(!connection.connected) {
      connection.write("AWAY\n");
      connection.connected=true;
    }
    if(newdevice) {
      connection.write("LUSERS\n");
      socket.write(":*jbnc 375 "+connection.nick+" :- Message of the Day -\n");
      socket.write(connection.motd+"\n");
      socket.write(":*jbnc 376 "+connection.nick+" :End of /MOTD command.\n");
    }

    socket.write(":*jbnc PRIVMSG "+connection.nick+" :Attaching you to the network\n");

    // Loop thru channels and send JOINs
    for(key in connection.channels) {
      if(connection.channels.hasOwnProperty(key)) {
        _channel=connection.channels[key];

        if (_channel && _channel.name) {
          if(connection.ircv3_extendedjoin)
            socket.write("@time="+new Date().toISOString()+";msgid=back :"+connection.nick+"!"+connection.ircuser+"@"+connection.host+" JOIN "+_channel.name+" "+(connection.account?connection.account:'*')+" :"+connection.realname+"\n");
          else
            socket.write("@time="+new Date().toISOString()+";msgid=back :"+connection.nick+"!"+connection.ircuser+"@"+connection.host+" JOIN :"+_channel.name+"\n");
        } else {
          console.error(`${parseInt(Number(new Date()) / 1000)}  Probleme bug undefined on join : ${JSON.stringify(_channel)}`);
          continue;
        }

        _mode_params='';
    
        if ( typeof _channel.modes === 'undefined' )
          _channel.modes = "";

        if ( typeof _channel.topic === 'undefined' )
          _channel.topic = "";
          
        for(x=0;x<_channel.modes.length;x++) {
          switch(_channel.modes[x]) {
            case 'k': _mode_params+=' '+_channel.key;
              break;
            case 'j': _mode_params+=' '+_channel.throttle;
              break;
            case 'l': _mode_params+=' '+_channel.limit;
              break;
            case 'f': _mode_params+=' '+_channel.forward;
              break;
            
            default:
              break;
          }
        }
        socket.write(":*jbnc 324 "+connection.nick+" "+key+" +"+_channel.modes+" "+_mode_params+"\n");
        if(_channel.topic.length>0) {
          socket.write(":*jbnc 332 "+connection.nick+" "+key+" :"+_channel.topic+"\n");
          socket.write(":*jbnc 333 "+connection.nick+" "+key+" "+_channel.topic_set+" "+_channel.topic_time+"\n");
        }
        if(DEBUG) {
          console.log(":*jbnc 324 "+connection.nick+" "+key+" +"+_channel.modes+" "+_mode_params);
          if(_channel.topic.length>0) {
            console.log(":*jbnc 332 "+connection.nick+" "+key+" :"+_channel.topic);
            console.log(":*jbnc 333 "+connection.nick+" "+key+" "+_channel.topic_set+" "+_channel.topic_time);
          }
        }
        
        for(x=0;x<_channel.names.length;x++) {
          if(x%53==0) {
            socket.write("\n");
            socket.write(":*jbnc 353 "+connection.nick+" = "+key+" :");
            if(DEBUG)
            console.log(":*jbnc 353 "+connection.nick+" = "+key+" :");
          }
          socket.write(_channel.names[x]);
          if(DEBUG)
          console.log(_channel.names[x]);
          if(x+1<_channel.names.length) {
            socket.write(" ");
          }
        }
        if(DEBUG)
        console.log("\n:*jbnc 366 "+connection.nick+" "+key+" :End of /NAMES list.\n");
        socket.write("\n:*jbnc 366 "+connection.nick+" "+key+" :End of /NAMES list.\n");
      }
    }
    
    socket.write(":"+connection.nick+" MODE "+connection.nick+" :+"+connection.umode+"\n");
    if(DEBUG)
      console.log(":"+connection.nick+" MODE "+connection.nick+" :+"+connection.umode)
    if(connection.buffers[socket.clientbuffer] && connection.buffers[socket.clientbuffer].data && connection.buffers[socket.clientbuffer].data.length>0) {
      socket.write(":*jbnc PRIVMSG "+connection.nick+" :Retrieving all messages\n");
      socket.write(connection.buffers[socket.clientbuffer].data+"\n");
      connection.buffers[socket.clientbuffer].data='';
      socket.write(":*jbnc PRIVMSG "+connection.nick+" :End of retrieving all messages\n");
    }
    else
    socket.write(":*jbnc PRIVMSG "+connection.nick+" :There is no new message\n");
  }
}

function clientConnect(socket) {
  let _success=true;
  let _connector=net.createConnection;
  let _tempport=socket.irc.port.toString();
  let _ssl=false;
  let _options = {
    rejectUnauthorized: true
  };
  if(_tempport.substr(0,1)=="+") {
    _connector=tls.connect;
    _tempport=parseInt(socket.irc.port.toString().substr(1));
    _ssl=true;
  }
  else if(_tempport.substr(0,1)=="=") {
    _connector=tls.connect;
    _tempport=parseInt(socket.irc.port.toString().substr(1));
    _ssl=true;
    _options = { rejectUnauthorized: false };
  }
  try {
    if(_ssl)
      connection = _connector(_tempport, socket.irc.server, _options);
    else
      connection = _connector(_tempport, socket.irc.server);
  } catch(e) {
    if(DEBUG) {
      console.log("Failed to connect to "+socket.irc.server+ ":"+__tempport);
    }
    _success=false;
  }
  if (socket.connected) 
    _success=false;		   
  if(_success) {
    if(DEBUG)
      console.log("Starting connect");
    // bouncer connections
    connection.parents = [];
    connection.parents[0] = socket;

    // client buffers
    connection.buffers = {};
    connection.buffers[socket.clientbuffer] = {data:'',connected:true};
    socket.connected=true;

    // irc server connection data
    connection.connectbuf='';
    connection.nick = socket.irc.nick;
    connection.nick_original = socket.irc.nick;
    connection.password = socket.irc.password;
    connection.nickpassword = socket.irc.nickpassword;
    connection.accountsasl = socket.irc.accountsasl;													  
    connection.user = socket.irc.user;
    connection.ircuser = socket.irc.user;
    connection.server = socket.irc.server;
    connection.port = socket.irc.port;
    connection.realname = socket.irc.realname;
    connection.hash = socket.hash;
    connection.serverpassword = socket.irc.serverpassword;
    connection.host = socket.host!=null?socket.host:(socket.remoteAddress.substr(0,7)=="::ffff:"?socket.remoteAddress.substr(7):socket.remoteAddress);
    connection.umode='';
    connection.motd='';
    connection.channels={};
    connection.authenticated = false;
    connection.connected = true;
    connection.opmode = BOUNCER_DEFAULT_OPMODE;
    connection.userhostInNames=false;
    connection.messagetags=false;
    connection.ircv3Monitor=false;
    connection.ircv3_extendedjoin=false;

    // Temp Buffer
    connection._buffer='';
    connection._getnames={};

    connection.on('connect',async function() {
      this.write("CAP LS 302\n");
      if(DEBUG)
        console.log("CAP LS 302");
      if(SERVER_WEBIRC.length>0) {
        if(this.host==":1")
          this.host="127.0.0.1";
        try {
          _reverse_ip = await reverse(this.host);
        } catch(e) {
          _reverse_ip = this.host;
        }
        if(false) { // My server irc
          _vhost = iphash(this.nick);
          this.write('WEBIRC '+SERVER_WEBIRC+' '+this.user+' galaxy-'+this.host+'.cloud-'+(_vhost?_vhost:'0')+'.jbnc '+this.host+' :secure\n');
        }
        else if(SERVER_WEBIRCHASHIP && !SERVER_WEBIRCPROXY) {
          this.write('WEBIRC '+SERVER_WEBIRC+' '+this.user+' jbnc.'+iphash(this.hostonce)+" "+this.host+"\n");
        }
        else if(SERVER_WEBIRCHASHIP && SERVER_WEBIRCPROXY) {
          this.write('WEBIRC '+SERVER_WEBIRC+' '+this.user+' jbnc.'+iphash(this.host)+" "+this.host+"\n");
        }
        else
          this.write('WEBIRC '+SERVER_WEBIRC+' '+this.user+' '+_reverse_ip+" "+this.host+"\n");
      }
      if(this.serverpassword) {
        this.write('PASS '+this.serverpassword+'\n');
      }
      this.write('NICK '+this.nick+'\n');
      this.write('USER '+this.user+' * 0 :'+this.realname+'\n');
      connections[hash(this.nick_original+this.password+this.server+this.port.toString())] = this;
      if(DEBUG)
        console.log("Connection created.");
    });
    connection.on('data', function(d){
      _d = this._buffer + d.toString();
      let lines = _d.toString().split('\n');
      if (lines[lines.length - 1] !== '') {
          this._buffer = lines.pop();
      } else {
          lines.pop();
          this._buffer = '';
      }
      
      if (true) {
        for(n=0;n<lines.length;n++) {
          if(DEBUG)
            console.log("> "+lines[n]);
          data = lines[n].trim().split(" ");
          if(data[1]=="CAP") {

            // :irc.example.net CAP * LS :invite-notify ...
            // :irc.example.net CAP * NEW :invite-notify ...
            if(data[3] && (data[3]=='LS' || data[3]==='NEW')) {
              
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

              // <- :irc.example.net CAP testor LIST :away-notify ...

              if (requestingCaps.includes("userhost-in-names"))
                this.userhostInNames=true;

              if (requestingCaps.includes("message-tags"))
                this.messagetags=true;
                
              if (requestingCaps.includes("sasl"))
                this.sasl=true;

              if (requestingCaps.includes("extended-join"))
                this.ircv3_extendedjoin=true;

              if (data[3]!=='NEW' && requestingCaps.length === 0) {
                this.write("CAP END\n");
              } else {
                this.write(`CAP REQ :${requestingCaps.join(' ')}\n`);
              }

            }
            else if(this.sasl && data[3] && data[3]=='ACK') {
              this.write("AUTHENTICATE PLAIN\n");
            }
            else {
              if (!this.sasl)
                this.write("CAP END\n");
            }
            continue;
          }
		  
          if(this.sasl && data[0]=="AUTHENTICATE" && data[1]=="+") {
            const auth_str = (this.accountsasl ? this.accountsasl : this.nick) + '\0' +
            (this.accountsasl ? this.accountsasl : this.nick) + '\0' +
            this.nickpassword;

            const b = Buffer.from(auth_str, 'utf8');
            const b64 = b.toString('base64');
    
            const singleAuthCommandLength = 400;
            let sliceOffset = 0;

            while (b64.length > sliceOffset) {
                this.write('AUTHENTICATE ' + b64.substr(sliceOffset, singleAuthCommandLength) + '\n');
                sliceOffset += singleAuthCommandLength;
            }

            if (b64.length === sliceOffset)
              this.write('AUTHENTICATE +\n');

            continue;
          }

          // :irc.server 904 <nick> :SASL authentication failed
          if(data[1]=="904") {
            if(!this.authenticated) {
              this.end();
              continue;
            }
          }

          // :x 903 y :SASL authentication successful
          if(data[1]=="903") {
            if(!this.authenticated) {
              this.write("CAP END\n");
            }
          }

          if(data[1]=="901") {
            this.account = '';
          }
		  
          if(data[1]=="900") {
            this.account = data[4];
          }
          let s = data[1];

          if ( this.messagetags && (data[2]=="JOIN" || data[2]=="PART" || data[2]=="QUIT" || data[2]=="MODE" || data[2]=="PING" || data[2]=="NICK" || data[2]=="KICK") ) {
            s = data[2];
          }

          switch(s) {
            case '001':
              if(!this.authenticated) {
                this.authenticated=true;
                this.nick_original=data[2];
                if(lines[n].lastIndexOf("@")>0) {
                  this.ircuser=lines[n].substr(lines[n].lastIndexOf("!")+1,lines[n].lastIndexOf("@")-lines[n].lastIndexOf("!")-1);
                  this.host=lines[n].substr(lines[n].lastIndexOf("@")+1).trim();
                }
                else
                  this.host="jbnc";
              }
            case '002':
            case '003':
            case '004':
            case '005':
              this.connectbuf+=lines[n]+"\n";
              break;
            case '324':
            case 'MODE':
              _mode_target=[];
              // <- :irc.jbnc.com 324 spawn #lu +CPTVnrst
              if (data[1]=='324') {
                _target=data[3].trim();
                _sender=data[0].substr(1).split("!")[0];
                _mode=data[4].trim();
                if(data[5])
                _mode_target = data.slice(5,data.length);
              }
              // <- @time=2020-09-16T22:25:40.594Z :spawn!spawn@chanroot/b3Az MODE #lu +m
              else if (this.messagetags && data[2]=='MODE') {
                _target=data[3].trim();
                _sender=data[1].substr(1).split("!")[0];
                _mode=data[4].trim();
                if(data[5])
                _mode_target = data.slice(5,data.length);
              }
              // :spawn!spawn@chanroot/b3Az MODE #lu +m
              else if (!this.messagetags && data[1]=='MODE') {
                _target=data[2].trim();
                _sender=data[0].substr(1).split("!")[0];
                _mode=data[3].trim();
                if(data[4])
                _mode_target = data.slice(4,data.length);
              }
              else {
                _target=data[2].trim();
                _sender=data[0].substr(1).split("!")[0];
                _mode=data[3].trim();
                if(data[4])
                _mode_target = data.slice(4,data.length);
              }

              _mode = _mode.indexOf(":")!=-1?_mode.substr(1):_mode;
              
              _mode_count = 0;
              _add = true;
              // walk thru modes
              for(i=0;i<_mode.length;i++) {
                let curchan=this.channels[_target.toLowerCase()];
                if(_mode[i]=='+')
                  _add=true;
                else if(_mode[i]=='-')
                  _add=false;
                else {
                  if(_add) {
                    if(_sender==_target && _target==this.nick || _sender=="NickServ" && _target==this.nick || _sender=="OperServ" && _target==this.nick) {
                      if(this.umode!=null && this.umode.indexOf(_mode[i])==-1) {
                        this.umode+=_mode[i];
                      }
                    }
                    else if(curchan!=null && (_mode[i]!='o' && _mode[i]!='k' && _mode[i]!='v' && _mode[i]!='h' && _mode[i]!='l')) {
                      if(curchan.modes!=null && curchan.modes.indexOf(_mode[i])==-1)
                        curchan.modes+=_mode[i];
                    }
                    else if((_target.indexOf("#")!=-1||_target.indexOf("&")!=-1) && (_mode[i]=='o' || _mode[i]=='k' || _mode[i]=='v' || _mode[i]=='h' || _mode[i]=='l' ||
                                                         _mode[i]=='e' || _mode[i]=='b' || _mode[i]=='I' || _mode[i]=='q' || _mode[i]=='f' ||
                                                         _mode[i]=='j')) {
                      if(_mode[i]=='o' || _mode[i]=='v' || _mode[i]=='h') {
                        for(c=0;c<curchan.names.length;c++) {
                          if(curchan.names[c].replace(/(&|~|@|%|\+)/,"")==_mode_target[_mode_count]) {
                            switch(_mode[i]) {
                              case 'o':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                if(curchan.names[c].indexOf("@")==-1) {
                                  curchan.names[c]="@"+curchan.names[c];
                                  if(_mode_target[_mode_count]!=this.nick && curchan.aop && curchan.aop.indexOf(_this_target)<0 && this.opmode) {
                                    curchan.aop.push(_this_target);
                                  }
                                }
                                if(_mode_target[_mode_count]==this.nick) curchan.isop=true;
                                break;
                              case 'v':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                if(curchan.names[c].indexOf("+")==-1) {
                                  if(curchan.names[c].indexOf("&")==-1 || curchan.names[c].indexOf("~")==-1 || curchan.names[c].indexOf("@")==-1) {
                                    if(curchan.names[c].indexOf("%")==-1) {
                                      curchan.names[c]="+"+curchan.names[c];
                                    }
                                    else {
                                      curchan.names[c]=curchan.names[c].substr(0,1)+"+"+curchan.names[c].substr(1);
                                    }
                                  }
                                  else {
                                    if(curchan.names[c].indexOf("%")==-1) {
                                      curchan.names[c]=curchan.names[c].substr(0,1)+"+"+curchan.names[c].substr(1);
                                    }
                                    else {
                                      curchan.names[c]=curchan.names[c].substr(0,2)+"+"+curchan.names[c].substr(2);
                                    }
                                  }
                                  if(_mode_target[_mode_count]!=this.nick && curchan.aov && curchan.aov.indexOf(_this_target)<0 && this.opmode) {
                                    curchan.aov.push(_mode_target[_this_target]);
                                  }
                                }
                                if(_mode_target[_mode_count]==this.nick) curchan.isvoice=true;
                                break;
                              case 'h':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                if(curchan.names[c].indexOf("%")==-1) {
                                  if(curchan.names[c].indexOf("&")==-1 || curchan.names[c].indexOf("~")==-1 || curchan.names[c].indexOf("@")==-1) {
                                    curchan.names[c]="%"+curchan.names[c];
                                  }
                                  else
                                    curchan.names[c]=curchan.names[c].substr(0,1)+"%"+curchan.names[c].substr(1);
                                  if(_mode_target[_mode_count]!=this.nick && curchan.aoh && curchan.aoh.indexOf(_this_target)<0 && this.opmode) {
                                    curchan.aoh.push(_mode_target[_this_target]);
                                  }
                                }
                                if(_mode_target[_mode_count]==this.nick) curchan.ishop=true;
                                break;
                            }
                          }
                        }
                        _mode_count++;
                        continue;
                      }
                      else {
                        if(_mode[i]=='k')
                          curchan.key=_mode_target[_mode_count];
                        else if(_mode[i]=='l')
                          curchan.limit=_mode_target[_mode_count];
                        else if(_mode[i]=='f')
                          curchan.forward=_mode_target[_mode_count];
                        else if(_mode[i]=='j')
                          curchan.throttle=_mode_target[_mode_count];

                        if(curchan.modes.indexOf(_mode[i])==-1)
                          curchan.modes+=_mode[i];
                        _mode_count++;
                      }
                    }
                  }
                  else {
                    _regex = new RegExp(_mode[i],"g");
                    if(_sender==_target && _target==this.nick || _sender=="NickServ" && _target==this.nick || _sender=="OperServ" && _target==this.nick)
                      this.umode=this.umode.replace(_regex,"");
                    else if(curchan != null && (_mode[i]!='o' && _mode[i]!='v' && _mode[i]!='h') && curchan.modes)
                      curchan.modes=curchan.modes.replace(_regex,"");
                    if((_target.indexOf("#")!=-1||_target.indexOf("&")!=-1) && (_mode[i]=='o' || _mode[i]=='k' || _mode[i]=='v' || _mode[i]=='h' || _mode[i]=='l' ||
                                                         _mode[i]=='e' || _mode[i]=='b' || _mode[i]=='I' || _mode[i]=='q' || _mode[i]=='f' ||
                                                         _mode[i]=='j')) {
                      if(_mode[i]=='o' || _mode[i]=='v' || _mode[i]=='h') {
                        for(c=0;c<curchan.names.length;c++) {
                          if(curchan.names[c].replace(/(&|~|@|%|\+)/,"")==_mode_target[_mode_count]) {
                            switch(_mode[i]) {
                              case 'o':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                curchan.names[c]=curchan.names[c].replace(/(&|~|@)/,"");
                                if(_mode_target[_mode_count]!=this.nick && curchan.aop && curchan.aop.indexOf(_this_target)>=0 && this.opmode) {
                                  curchan.aop.splice(curchan.aop.indexOf(_this_target),1);
                                }
                                if(_mode_target[_mode_count]==this.nick) this.isop=false;
                                break;
                              case 'v':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                curchan.names[c]=curchan.names[c].replace("+","");
                                if(_mode_target[_mode_count]!=this.nick && curchan.aov && curchan.aov.indexOf(_this_target)>=0 && this.opmode) {
                                  curchan.aov.splice(curchan.aov.indexOf(_this_target),1);
                                }
                                if(_mode_target[_mode_count]==this.nick) this.isvoice=false;
                                break;
                              case 'h':
                                _this_target = _mode_target[_mode_count] + "!" + (curchan.userhosts[c]?curchan.userhosts[c]:"*@*");
                                curchan.names[c]=curchan.names[c].replace("%","");
                                if(_mode_target[_mode_count]!=this.nick && curchan.aoh && curchan.aoh.indexOf(_this_target)>=0 && this.opmode) {
                                  curchan.aoh.splice(curchan.aoh.indexOf(_this_target),1);
                                }
                                if(_mode_target[_mode_count]==this.nick) this.ishop=false;
                                break;
                            }
                          }
                        }
                        _mode_count++;
                        continue;
                      }
                      else {
                        if(_mode[i]=='k') {
                          curchan.key=null;
                          _mode_count++;
                        }
                        else if(_mode[i]=='l')
                          curchan.limit=null;
                        else if(_mode[i]=='j')
                          curchan.throttle=null;
                        else if(_mode[i]=='f')
                          curchan.forward=null;
                      }
                    }

                  }
                }
              }
              break;
            case '375':
              this.motd='';
              break;
            case '372':
              this.motd+=lines[n]+"\n";
              break;
            case 'JOIN':
              _temp = (this.messagetags ? data[1].substr(1).split("!") : data[0].substr(1).split("!"));
              _datatemp = (this.messagetags ? 3 : 2);
              _nick = _temp[0];
              if(_temp[1])
                _userhost = _temp[1];
              if(_temp[1] && this.nick==_nick) {
                this.ircuser=_temp[1].split("@")[0];
              }
              _channels = data[_datatemp].substr(0).trim().split(",");
              if(data[_datatemp].indexOf(":")!=-1)
                _channels = data[_datatemp].substr(1).trim().split(",");
              for(x=0;x<_channels.length;x++) {
                _channel=_channels[x];
                __channel=_channel.toLowerCase();
                if(_nick==this.nick) {
                  if(!this.channels[__channel]) {
                    this.channels[__channel]={};
                    this.channels[__channel].modes='';
                    this.channels[__channel].topic='';
                    this.channels[__channel].topic_set='';
                    this.channels[__channel].topic_time=0;
                    this.channels[__channel].key=null;
                    this.channels[__channel].limit=null;
                    this.channels[__channel].forward=null;
                    this.channels[__channel].throttle=null;
                    this.channels[__channel].names=[];
                    this.channels[__channel].userhosts=[];
                    this.channels[__channel].name=_channel;
                    this.channels[__channel].aop=[];
                    this.channels[__channel].aoh=[];
                    this.channels[__channel].aov=[];
                    this.channels[__channel].isop=false;
                    this.channels[__channel].ishop=false;
                    this.channels[__channel].isvoice=false;
                  }
                  if(this.channels[__channel]) {
                    this.channels[__channel].name=_channel;
                  }
                }
                else {
                  if(this.channels[__channel]) {
                    this.channels[__channel].name=_channel;
                    this.channels[__channel].names.push(_nick);
                    this.channels[__channel].userhosts.push(!!_userhost?_userhost:"*@*");
                    if(this.channels[__channel].isop && this.channels[__channel].aop && this.channels[__channel].aop.indexOf(_nick+"!"+_userhost)>=0 && this.opmode) {
                      this.write("MODE "+this.channels[__channel].name+" +o "+_nick+"\n");
                    }
                    if((this.channels[__channel].isop || this.channels[__channel].ishop) && this.channels[__channel].aoh && this.channels[__channel].aoh.indexOf(_nick+"!"+_userhost)>=0 && this.opmode) {
                      this.write("MODE "+this.channels[__channel].name+" +h "+_nick+"\n");
                    }
                    if((this.channels[__channel].isop || this.channels[__channel].ishop) && this.channels[__channel].aov && this.channels[__channel].aov.indexOf(_nick+"!"+_userhost)>=0 && this.opmode) {
                      this.write("MODE "+this.channels[__channel].name+" +v "+_nick+"\n");
                    }
                  }
                }
              }
              break;
            case 'TOPIC':
              _target=data[2].toLowerCase().trim();
              _topic=lines[n].substr(lines[n].substr(1).indexOf(":")+2).trim();
              if(this.channels[_target]) {
                this.channels[_target].topic=_topic;
                this.channels[_target].topic_set=data[0].substr(1).split("!")[0];
                this.channels[_target].topic_time=Math.floor(new Date() / 1000);
              }
              break;
            case '332':
              _target=data[3].toLowerCase().trim();
              _topic=lines[n].substr(lines[n].substr(1).indexOf(":")+2).trim();
              if(!this.channels[_target])
                this.channels[_target]={};
              this.channels[_target].topic=_topic;
              break;
            case '333':
              _channel=data[3].toLowerCase().trim();
              _setter=data[4].split("!")[0].trim();
              _time=data[5].trim();
              if(!this.channels[_channel])
                this.channels[_channel]={};
              this.channels[_channel].topic_set=_setter;
              this.channels[_channel].topic_time=_time;
              break;
            case 'KICK':
              _target=(this.messagetags ? data[4].trim() : data[3].trim());
              _channel=(this.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
              if(_target==this.nick) {
                delete this.channels[_channel];
              }
              else if(this.channels[_channel]) {
                for(x=0;x<this.channels[_channel].names.length;x++)
                  if(this.channels[_channel].names[x].replace(/(&|~|@|%|\+)/,"")==_target)
                    break;
                this.channels[_channel].names.splice(x,1);
              }
              break;
            case 'PART':
              _target=(this.messagetags ? data[3].toLowerCase().trim() : data[2].toLowerCase().trim());
              _sender=(this.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
              if(_sender==this.nick) {
                delete this.channels[_target];
              }
              else if(this.channels[_target]) {
                for(x=0;x<this.channels[_target].names.length;x++)
                  if(this.channels[_target].names[x].replace(/(&|~|@|%|\+)/,"")==_sender)
                    break;
                this.channels[_target].names.splice(x,1);
                this.channels[_target].userhosts.splice(x,1);
              }
              break;
            case 'QUIT':
              _sender=(this.messagetags ? data[1].substr(1).split("!")[0] : data[0].substr(1).split("!")[0]);
              for (key in this.channels) {
                if (this.channels.hasOwnProperty(key)) {
                  for(x=0;x<this.channels[key].names.length;x++) {
                    if(this.channels[key].names[x].replace(/(&|~|@|%|\+)/,"")==_sender) {
                    this.channels[key].names.splice(x,1);
                    this.channels[key].userhosts.splice(x,1);
                    break;
                    }
                  }
                }
              }
              break;
            case '353':
              _channel=data[4].toLowerCase().trim();
              _names=lines[n].substr(1).split(" :")[1].trim().split(" ");
              if (!this.channels[_channel])
              break;
              if(!this._getnames[_channel]) {
                this._getnames[_channel]=true;
                if(!this.channels[_channel]) {
                  this.channels[_channel]={};
                }
                this.channels[_channel].names=[];
              }
              for(x=0;x<_names.length;x++) {
                if (!this.channels[_channel])
                break;
                this.channels[_channel].names.push(_names[x].trim().split("!")[0]);

                if (typeof this.channels[_channel].userhosts === 'undefined')
                  this.channels[_channel].userhosts=[];

                if(_names[x].trim().indexOf("!")>=0)
                  this.channels[_channel].userhosts.push(_names[x].trim().split("!")[1]);
                /*else
                  this.channels[_channel].userhosts.push("*@*");	*/						
              }
              break;
            case '366':
              _channel=data[3].toLowerCase().trim();
              this._getnames[_channel]=false;
              break;
            case 'NICK':
              _sender = data[1].substr(1).split("!")[0];
              _new = data[3].substr(1).trim();

              if(_sender==this.nick) {
                this.nick=_new;
              }

              for (key in this.channels) {
                if (this.channels.hasOwnProperty(key)) {
                  for(x=0;x<this.channels[key].names.length;x++) {
                    if(this.channels[key].names[x].replace(/(&|~|@|%|\+)/,"")==_sender) {
                      _statut = ( /(&|~|@|%|\+)/.test(this.channels[key].names[x].substr(0,1)) ? this.channels[key].names[x].substr(0,1) : "" );
                    this.channels[key].names.splice(x,1);
                    this.channels[key].names.push(_statut+_new);
                    break;
                    }
                  }
                }
              }
              break;
            case '433':
              if(this.parents.length==0) {
                if(data[2]=='*') {
                  this.write("NICK "+data[3].trim()+"_"+"\n");
                  this.nick=data[3].trim()+"_";
                }
              }
              break;
          }
          if(data[1] == "PING") {
            this.write("PONG "+data[2].substr(1).trim()+"\n");
            continue;
          }
          if(data[0] == "PING") {
            this.write("PONG "+data[1].substr(1).trim()+"\n");
            continue;
          }
          if(lines[n].length>1) {
            for(m=0;m<this.parents.length;m++) {
              this.parents[m].write(lines[n]+"\n");
            }
          }
          // store clientbuf if not connected
          if(lines[n].indexOf("PRIVMSG")>=0 || lines[n].indexOf("NOTICE")>=0 || lines[n].indexOf("WALLOPS")>=0 || lines[n].indexOf("GLOBOPS")>=0 || lines[n].indexOf("CHATOPS")>=0) {
            for(key in this.buffers) {
              if(this.buffers.hasOwnProperty(key)) {
                if(!this.buffers[key].connected) {
                  this.buffers[key].data+=lines[n]+"\n";
				  
                  // Temporary: replace this system with "PRIVMSG_LINEMAX" ...
                  _split = this.buffers[key].data.split("\n");
                  if(_split.length>=BUFFER_LINEMAX && BUFFER_LINEMAX!=0) {
                    _split.splice(0, _split.length-BUFFER_LINEMAX);
                    _line = "";
                    for (t=0; t<_split.length; t++) {
                      _line += _split[t]+"\n";
                    }
                    this.buffers[key].data=_line;
                  }
                }
              }
            }
          }
        }
      }
    });
    connection.on('close', function() {
      for(x=0;x<this.parents.length;x++) {
        clearInterval(this.parents[x].pings);
        this.parents[x].write(":"+this.nick + " QUIT :QUIT");
        this.parents[x].end();
      }
      this.buffers=false;
      delete connections[hash(this.nick+this.password+this.server+this.port.toString())];
      this.destroy();
    });
    connection.on('error', function(err) {
      this.end();
    });
  }
  else {
    socket.end();
  }
}
if(BOUNCER_IP)
  server.listen(BOUNCER_PORT, BOUNCER_IP);
else
  server.listen(BOUNCER_PORT);

