// jbnc v0.3
// Copyright (C) 2020 Andrew Lee <andrew@imperialfamily.com>
// All Rights Reserved.
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const crypto = require("crypto");

// Load jbnc.conf
_config = process.argv[2]?process.argv[2]:"jbnc.conf";
var config = {};
if(fs.existsSync(_config)) config = JSON.parse(fs.readFileSync(_config));
else process.exit(1);

// Set config vars
const BOUNCER_PORT = config.bouncerPort?config.bouncerPort:8888;
const BOUNCER_PASSWORD = config.bouncerPassword?config.bouncerPassword:'';
const BOUNCER_ADMIN = config.bouncerAdmin?config.bouncerAdmin:'';
const BOUNCER_MODE = config.mode?config.mode:'bouncer';
const SERVER_WEBIRC = config.webircPassword?webircPassword:'';
const SERVER_PORT = BOUNCER_MODE=='gateway'?(config.serverPort?config.serverPort:0):0;
const SERVER = BOUNCER_MODE=='gateway'?(config.server?config.server:''):'';
const DEBUG = config.debug?config.debug:false;

// Track IRC (Server) Connections
var connections={};

// Helper Functions
function hash(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('base64');
}

// Bouncer Server
const server = net.Server();
server.listen(BOUNCER_PORT);
var users=0;
server.on('connection', function(socket) {
  // Used for auth
  socket.badauth=false;
  socket.irc={};

  // Track connection type
  socket.connected=false;

  // Connection ID
  socket.hash='';

  // Miscellaneous
  socket.clientbuffer='default';
  socket.cap=false; // IRCv3 CAP (only znc.in/self-message)
  socket.capready=false;
  socket.admin=false;  // Is user an admin
  users++;

  // Temp Buffer
  socket._buffer='';
  socket._outbuffer=''; // Just used at the beginning only

  socket.on('data', function(chunk) {
    let _chunk = chunk.toString();
    if(_chunk.substr(_chunk.length-1)!="\n")
      this._buffer+=_chunk;
    else {
      let input = (this._buffer + _chunk.trim());
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

                  origin = commands[1].trim().split("/");
                  if(origin[0].indexOf("||")>0)
                    this.irc.password = origin[0].split("||")[1];
                  else
                    this.irc.password = origin[0];

                  if(BOUNCER_MODE=="gateway") {
                    if(origin.length!=1 && origin.length!=2)
                      this.end();
                    else {
                      if(origin[1])
                        this.clientbuffer=origin[1].trim();
                    }
                  }
                  else {
                    if(origin.length!=2 && origin.length!=3)
                      this.end();
                    else {
                      _server = origin[1].split(":");
                      this.irc.server = _server[0];
                      this.irc.port = (_server[1] ? _server[1].trim() : 6667);
                      if(origin[2])
                        this.irc.buffer=origin[2].trim();
                    }
                  }
                }
              }
              break;
            case 'NICK':
              if(commands[1])
                this.irc.nick=commands[1].trim();
              break;
            case 'USER':
              if(commands.length >= 5) {
                this.irc.user = commands[1].trim();
                this.irc.realname = input[i].split(" :").pop().trim();
                this.hash=hash(this.irc.nick+this.irc.user+this.irc.password+this.irc.server+this.irc.port.toString());
                if(!this.cap) {
                  if(connections[socket.hash]) {
                    clientReconnect(this);
                  }
                  else {
                    clientConnect(this);
                  }
                }
                else {
                  this.capready=true;
                }
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
            case 'QUIT':
              this.end();
              break;
            case 'NICK':
              if(this.hash && connections[this.hash] && command[1]) {
                connections[this.hash].write("NICK "+command[1]+"\n");
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
                    connections[this.hash].end();
                    break;
                  case 'PASS':
                    if(command[3]) {
                      if(command[2]==connections[this.hash].password) {
                        connections[this.hash].password=command[3];
                        this.irc.password=command[3];
                        this.write(":*jbnc NOTICE * :Password changed to "+command[3]+"\n");
                        _newhash=hash(this.irc.nick+this.irc.user+this.irc.password+this.irc.server+this.irc.port.toString());
                        connections[_newhash]=connections[this.hash];
                        delete connections[this.hash];
                        this.hash=_newhash;
                      }
                      else
                        this.write(":*jbnc NOTICE * :Incorrect password.\n");
                    }
                    else
                      this.write(":*jbnc NOTICE * :Syntax error.\n");
                      this.write(":*jbnc NOTICE * :PASS <old password> <new password>.\n");
                    break;
                  default:
                    this.write(":*jbnc NOTICE * :Unknown command.\n");
                    break;
                }
                break;
              }
              break;
            default:
              // supress joins of channels we are already in because some clients dont react properly.
              if(input[i].toString().substr(0,4)=="JOIN") {
                command=input[i].toString().trim().split(" ");
                channels=command[1].split(",");
                if(command[2])
                  passwords=command[2].split(",");
                l=0;
                for(m=0;m<channels.length;m++) {
                  if(connections[this.hash].channels[channels[m].trim().toUpperCase()]) {
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
              if(connections[this.hash] && connections[this.hash].authenticated) {
                connections[this.hash].write(input[i].toString() + "\n");
                for(m=0;m<connections[this.hash].parents.length;m++) {
                  if(connections[this.hash].parents[m]==this)
                    continue;
                  else {
                    connections[this.hash].parents[m].write(":"+connections[this.hash].nick+" "+input[i].toString() + "\n");
                  }
                }
                if(input[i].toString().substr(0,7)=="PRIVMSG" || input[i].toString().substr(0,6)=="NOTICE") {
                  for(key in connections[this.hash].buffers) {
                    if(connections[this.hash].buffers.hasOwnProperty(key)) {
                      if(!connections[this.hash].buffers[key].connected) {
                        connections[this.hash].buffers[key].data+=":"+connections[this.hash].nick+"!"+connections[this.hash].ircuser+"@"+connections[this.hash].host+" "+input[i]+"\n";
                      }
                    }
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
    if(connections[this.hash] && connections[this.hash].buffers[this.clientbuffer]) {
      connections[this.hash].buffers[this.clientbuffer].connected=false;
    }
    if(connections[this.hash]) {
      for(i=0;i<connections[this.hash].parents.length;i++) {
        if(connections[this.hash].parents[i]==this)
          break;
      }
      connections[this.hash].parents.splice(i,1);
      if(connections[this.hash].parents.length==0) {
        connections[this.hash].connected=false;
        connections[this.hash].write("AWAY :jbnc\n");
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
  let connection=connections[socket.hash];
  connection.parents[connection.parents.length] = socket;
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

  // Loop thru channels and send JOINs
  for(key in connection.channels) {
    if(connection.channels.hasOwnProperty(key)) {
      _channel=connection.channels[key];

      socket.write(":"+connection.nick+"!"+connection.ircuser+"@"+connection.host+" JOIN :"+_channel.name+"\n");
      _mode_params='';
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
      socket.write(":*jbnc 332 "+connection.nick+" "+key+" :"+_channel.topic+"\n");
      socket.write(":*jbnc 333 "+connection.nick+" "+key+" "+_channel.topic_set+" "+_channel.topic_time+"\n");
      for(x=0;x<_channel.names.length;x++) {
        if(x%53==0) {
          socket.write("\n");
          socket.write(":*jbnc 353 "+connection.nick+" = "+key+" :");
        }
        socket.write(_channel.names[x]);
        if(x+1<_channel.names.length) {
          socket.write(" ");
        }
      }
      socket.write("\n:*jbnc 366 "+connection.nick+" "+key+" :End of /NAMES list.\n");
    }
  }

  socket.write(":"+connection.nick+" MODE "+connection.nick+" :+"+connection.umode+"\n");
  if(connection.buffers[socket.clientbuffer].data.length>0) {
    socket.write(connection.buffers[socket.clientbuffer].data+"\n");
    connection.buffers[socket.clientbuffer].data='';
  }
}

function clientConnect(socket) {
  let _success=true;
  let _connector=net.createConnection;
  if(socket.irc.port.toString().substr(0,1)=="+") {
    _connector=tls.connect;
    socket.irc.port=parseInt(socket.irc.port.toString().substr(1));
  }
  try {
    connection = _connector(socket.irc.port, socket.irc.server);
  } catch(e) {
    _success=false;
  }
  if(_success) {
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
    connection.user = socket.irc.user;
    connection.ircuser = socket.irc.user;
    connection.server = socket.irc.server;
    connection.port = socket.irc.port;
    connection.realname = socket.irc.realname;
    connection.host = socket.remoteAddress.substr(0,7)=="::ffff:"?socket.remoteAddress.substr(7):socket.remoteAddress;
    connection.umode='';
    connection.motd='';
    connection.channels={};
    connection.authenticated = false;
    connection.connected = true;

    // Temp Buffer
    connection._buffer='';
    connection._getnames={};

    connection.on('connect',function() {
      if(SERVER_WEBIRC.length>0) {
        this.write('WEBIRC '+SERVER_WEBIRC+' '+this.user+' '+'jbnc'+" "+this.host+"\n");
      }
      this.write('NICK '+this.nick+'\n');
      this.write('USER '+this.user+' localhost '+this.server+' :'+this.realname+'\n');
      connections[hash(this.nick_original+this.user+this.password+this.server+this.port.toString())] = this;
    });
    connection.on('data', function(d){
      if(d.toString().substr(d.length-1)!="\n")
        this._buffer+=d.toString();
      else {
        _d = this._buffer + d.toString();
        this._buffer='';
        lines= _d.split("\n");
        for(n=0;n<lines.length;n++) {
          if(DEBUG)
            console.log("> "+lines[n]);
          data = lines[n].split(" ");
          switch(data[1]) {
            case '001':

              if(!this.authenticated) {
                this.authenticated=true;
                this.name_original=data[2];
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
              _target=data[1]=='324'?data[3].trim():data[2].trim();
              _sender=data[0].substr(1).split("!")[0];
              _mode = data[1]=='324'?data[4].trim():data[3].trim();
              _mode = _mode.indexOf(":")!=-1?_mode.substr(1):_mode;
              _mode_target = (data[1]=='324'?(data[5]?data[5].trim():null):(data[4]?data[4].trim():null));
              _mode_target = (!_mode_target?null:_mode_target.split(' '));
              _mode_count = 0;
              _add = true;
              // walk thru modes
              for(i=0;i<_mode.length;i++) {
                if(_mode[i]=='+')
                  _add=true;
                else if(_mode[i]=='-')
                  _add=false;
                else {
                  if(_add) {
                    if(_sender==_target && _target==this.nick) {
                      if(this.umode.indexOf(_mode[i])==-1)
                        this.umode+=_mode[i];
                    }
                    else if(this.channels[_target.toUpperCase()]  && (_mode[i]!='o' && _mode[i]!='k' && _mode[i]!='v' && _mode[i]!='h' && _mode[i]!='l')) {
                      if(this.channels[_target.toUpperCase()].modes.indexOf(_mode[i])==-1)
                        this.channels[_target.toUpperCase()].modes+=_mode[i];
                    }
                    else if((_target.indexOf("#")!=-1||_target.indexOf("&")!=-1) && (_mode[i]=='o' || _mode[i]=='k' || _mode[i]=='v' || _mode[i]=='h' || _mode[i]=='l' ||
                                                         _mode[i]=='e' || _mode[i]=='b' || _mode[i]=='I' || _mode[i]=='q' || _mode[i]=='f' ||
                                                         _mode[i]=='j')) {
                      if(_mode[i]=='o' || _mode[i]=='v' || _mode[i]=='h') {
                        for(c=0;c<this.channels[_target.toUpperCase()].names.length;c++) {
                          if(this.channels[_target.toUpperCase()].names[c].replace("@","").replace("+","").replace("%","")==_mode_target[_mode_count]) {
                            switch(_mode[i]) {
                              case 'o':
                                if(this.channels[_target.toUpperCase()].names[c].indexOf("@")==-1)
                                  this.channels[_target.toUpperCase()].names[c]="@"+this.channels[_target.toUpperCase()].names[c];
                                break;
                              case 'v':
                                if(this.channels[_target.toUpperCase()].names[c].indexOf("+")==-1)
                                  this.channels[_target.toUpperCase()].names[c]="+"+this.channels[_target.toUpperCase()].names[c];
                                break;
                              case 'h':
                                if(this.channels[_target.toUpperCase()].names[c].indexOf("%")==-1)
                                  this.channels[_target.toUpperCase()].names[c]="%"+this.channels[_target.toUpperCase()].names[c];
                                break;
                            }
                          }
                        }
                        _mode_count++;
                        continue;
                      }
                      else {
                        if(_mode[i]=='k')
                          this.channels[_target.toUpperCase()].key=_mode_target[_mode_count];
                        else if(_mode[i]=='l')
                          this.channels[_target.toUpperCase()].limit=_mode_target[_mode_count];
                        else if(_mode[i]=='f')
                          this.channels[_target.toUpperCase()].forward=_mode_target[_mode_count];
                        else if(_mode[i]=='j')
                          this.channels[_target.toUpperCase()].throttle=_mode_target[_mode_count];

                        if(this.channels[_target.toUpperCase()].modes.indexOf(_mode[i])==-1)
                          this.channels[_target.toUpperCase()].modes+=_mode[i];
                        _mode_count++;
                      }
                    }
                  }
                  else {
                    _regex = new RegExp(_mode[i],"g")
                    if(_sender==_target && _target==this.nick)
                      this.umode=this.umode.replace(_regex,"");
                    else if(this.channels[_target.toUpperCase()] && (_mode[i]!='o' && _mode[i]!='v' && _mode[i]!='h'))
                      this.channels[_target.toUpperCase()].modes=this.channels[_target.toUpperCase()].modes.replace(_regex,"");
                    if((_target.indexOf("#")!=-1||_target.indexOf("&")!=-1) && (_mode[i]=='o' || _mode[i]=='k' || _mode[i]=='v' || _mode[i]=='h' || _mode[i]=='l' ||
                                                         _mode[i]=='e' || _mode[i]=='b' || _mode[i]=='I' || _mode[i]=='q' || _mode[i]=='f' ||
                                                         _mode[i]=='j')) {
                      if(_mode[i]=='o' || _mode[i]=='v' || _mode[i]=='h') {
                        for(c=0;c<this.channels[_target.toUpperCase()].names.length;c++) {
                          if(this.channels[_target.toUpperCase()].names[c].replace(/\@/,"").replace(/\%/,"").replace(/\+/,"")==_mode_target[_mode_count]) {
                            switch(_mode[i]) {
                              case 'o':
                                this.channels[_target.toUpperCase()].names[c]=this.channels[_target.toUpperCase()].names[c].replace("@","");;
                                break;
                              case 'v':
                                this.channels[_target.toUpperCase()].names[c]=this.channels[_target.toUpperCase()].names[c].replace("+","");;
                                break;
                              case 'h':
                                this.channels[_target.toUpperCase()].names[c]=this.channels[_target.toUpperCase()].names[c].replace("%","");;
                                break;
                            }
                          }
                        }
                        _mode_count++;
                        continue;
                      }
                      else {
                        if(_mode[i]=='k') {
                          this.channels[_target.toUpperCase()].key=null;
                          _mode_count++;
                        }
                        else if(_mode[i]=='l')
                          this.channels[_target.toUpperCase()].limit=null;
                        else if(_mode[i]=='j')
                          this.channels[_target.toUpperCase()].throttle=null;
                        else if(_mode[i]=='f')
                          this.channels[_target.toUpperCase()].forward=null;
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
              _temp = data[0].substr(1).split("!");
              _nick = _temp[0];
              if(_temp[1])
                this.ircuser=_temp[1].split("@")[0];
              _channels = data[2].substr(0).trim().split(",");
              if(data[2].indexOf(":")!=-1)
                _channels = data[2].substr(1).trim().split(",");
              for(x=0;x<_channels.length;x++) {
                _channel=_channels[x];
                __channel=_channel.toUpperCase();
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
                    this.channels[__channel].name=_channel;
                  }
                }
                else {
                  if(this.channels[__channel]) {
                    this.channels[__channel].names[this.channels[__channel].names.length]=_nick;
                  }
                }
              }
              break;
            case 'TOPIC':
              _target=data[2].toUpperCase().trim();
              _topic=lines[n].substr(lines[n].substr(1).indexOf(":")+2).trim();
              if(this.channels[_target]) {
                this.channels[_target].topic=_topic;
                this.channels[_target].topic_set=data[0].substr(1).split("!")[0];
                this.channels[_target].topic_time=Math.floor(new Date() / 1000);
              }
              break;
            case '332':
              _target=data[3].toUpperCase().trim();
              _topic=lines[n].substr(lines[n].substr(1).indexOf(":")+2).trim();
              if(!this.channels[_target])
                this.channels[_target]={};
              this.channels[_target].topic=_topic;
              break;
            case '333':
              _channel=data[3].toUpperCase().trim();
              _setter=data[4].split("!")[0].trim();
              _time=data[5].trim();
              if(!this.channels[_channel])
                this.channels[_channel]={};
              this.channels[_channel].topic_set=_setter;
              this.channels[_channel].topic_time=_time;
              break;
            case 'KICK':
              _target=data[3].trim();
              _channel=data[2].toUpperCase().trim();
              if(_target==this.nick) {
                delete this.channels[_channel];
              }
              else if(this.channels[_channel]) {
                for(x=0;x<this.channels[_channel].names.length;x++)
                  if(this.channels[_channel].names[x].replace("@","").replace("\+","").replace("~","").replace("%","")==_target)
                    break;
                this.channels[_channel].names.splice(x,1);
              }
              break;
            case 'PART':
              _target=data[2].toUpperCase().trim();
              _sender=data[0].substr(1).split("!")[0];
              if(_sender==this.nick) {
                delete this.channels[_target];
              }
              else if(this.channels[_target]) {
                for(x=0;x<this.channels[_target].names.length;x++)
                  if(this.channels[_target].names[x].replace("@","").replace("\+","").replace("~","").replace("%","")==_sender)
                    break;
                this.channels[_target].names.splice(x,1);
              }
              break;
            case 'QUIT':
              _sender=data[0].substr(1).split("!")[0];
              for (key in this.channels) {
                if (this.channels.hasOwnProperty(key)) {
                  for(x=0;x<this.channels[key].names.length;x++)
                    if(this.channels[key].names[x].replace("@","").replace("\+","").replace("~","").replace("%","")==_sender)
                      break;
                  this.channels[key].names.splice(x,1);
                }
              }
              break;
            case '353':
              _channel=data[4].toUpperCase().trim();
              _names=lines[n].substr(1).split(" :")[1].trim().split(" ");
              if(!this._getnames[_channel]) {
                this._getnames[_channel]=true;
                if(!this.channels[_channel]) {
                  this.channels[_channel]={};
                  this.channels[_channel].names=[];
                }
              }
              for(x=0;x<_names.length;x++)
                this.channels[_channel].names[this.channels[_channel].names.length]=_names[x].trim();
              break;
            case '366':
              _channel=data[3].toUpperCase().trim();
              this._getnames[_channel]=false;
              break;
            case 'NICK':
              if(data[0].substr(1).split("!")[0]==this.nick) {
                this.nick=data[2].substr(1).trim();
              }
              break;
            case '433':
              if(data[2]=='*') {
                this.write("NICK "+data[3].trim()+"_"+"\n");
                this.nick=data[3].trim()+"_";
              }
              break;
          }
          if(data[0] == "PING")
            this.write("PONG "+data[1].substr(1).trim()+"\n");
          for(m=0;m<this.parents.length;m++)
            this.parents[m].write(lines[n]+"\n");

          // store clientbuf if not connected
          if(lines[n].indexOf("PRIVMSG")>=0 || lines[n].indexOf("NOTICE")>=0) {
            for(key in this.buffers) {
              if(this.buffers.hasOwnProperty(key)) {
                if(!this.buffers[key].connected) {
                  this.buffers[key].data+=lines[n]+"\n";
                }
              }
            }
          }
        }
      }
    });
    connection.on('close', function() {
      for(x=0;x<this.parents.length;x++) {
        this.parents[x].write(":"+this.nick + " QUIT :QUIT");
        this.parents[x].end();
      }
      this.buffers=false;
      delete connections[hash(this.nick+this.user+this.password+this.server+this.port.toString())];
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

