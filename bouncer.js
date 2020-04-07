// jbnc v0.1
// Copyright (C) 2020 Andrew Lee <andrew@imperialfamily.com>
// All Rights Reserved.
const tls = require('tls');
const net = require('net');
const server = net.Server();

const SERVER_PASSWORD='';  // Leave blank for none, if you set one it will be mandatory.

// Track IRC (Server) Connections
var connections=[];
function getConnection(irc) {
  let i;
  for(i=0;i<connections.length;i++) {
    if(connections[i].irc.password==irc.password &&
      connections[i].irc.server==irc.server &&
      connections[i].irc.nick_original==irc.nick &&
      connections[i].irc.port==irc.port &&
      connections[i].irc.user==irc.user) {
      break;
    }
  }
  if(i==connections.length) {
    return -1;
  }
  else
    return i;
}

// Bouncer Server
server.listen(8888);
server.on('connection', function(socket) {
  socket.wrong=false;
  socket.on('data', async function(chunk) {
    let input = chunk.toString().trim().split("\n");
    for(i=0;i<input.length;i++) {
      let commands=input[i].split(" ");
      let command=commands[0].toUpperCase();
      if(!this.irc || !this.irc.connected && !this.wrong ) {
        if(command=="PASS" && commands.length==2) {
          if(SERVER_PASSWORD.length>0 && commands[1].split("||")[0]!=SERVER_PASSWORD) {
            this.write(":jbnc 464 :*** Incorrect Password ***\n");
            this.wrong=true;
            this.end();
          }
          else {
            this.irc={
              server:null,
              port:0,
              nick:null,
              nick_original:null,
              namechange:null,
              user:null,
              realname:null,
              password:null,
              authenticated:false,
              reconnecting:false,
              buffer:'default',  // name of clientbuf
              connected:false,
              doclose:false
            };

            origin = commands[1].trim().split("/");
            if(origin.length!=2 && origin.length!=3)
              this.end();
            else {
              if(origin[0].indexOf("||")>=0)
                this.irc.password = origin[0].split("||")[1];
              else
                this.irc.password=origin[0];
              _server = origin[1].split(":");
              this.irc.server = _server[0];
              this.irc.port = (_server[1] ? _server[1].trim() : 6667);
              if(origin[2])
                this.irc.buffer=origin[2].trim();
            }
          }
        }
        else if(command=="NICK" && commands.length==2 && !this.wrong) {
          this.irc.nick=commands[1].trim();
        }
        else if(command=="USER" && commands.length>=5 && !this.wrong) {
          this.irc.user = commands[1].trim();
          this.irc.realname = input[i].split(" :").pop();

          c=getConnection(this.irc);
          if(c!=-1) {
            await clientReconnect(this,c);
          }
          else {
            await clientConnect(this);
          }
        }
        else
          if(command!="CAP") {
            this.end();
          }
      }
      else if(!this.wrong) {
        if(this.connection && this.connection.irc.authenticated) {
          command = input[i].toString().split(" ");
          switch(command[0]) {
            case 'QUIT':
              break;
            case 'JBNC':
              if(!command[1]) {
                this.write(":*jbnc NOTICE * :Welcome to JBNC\n");
                this.write(":*jbnc NOTICE * :***************\n");
                this.write(":*jbnc NOTICE * :Type /JBNC <COMMAND>\n");
                this.write(":*jbnc NOTICE * :Commands:\n");
                this.write(":*jbnc NOTICE * :QUIT - Disconnects and deletes your profile\n");
                this.write(":*jbnc NOTICE * :PASS - Change your password\n");
                this.write(":*jbnc NOTICE * :***************\n");
              }
              else {
                switch(command[1].toUpperCase()) {
                  case 'QUIT':
                    this.write(":*jbnc NOTICE * :Sayonara.\n");
                    this.connection.irc.doclose=true;
                    this.connection.end();
                    break;
                  case 'PASS':
                    if(command[3]) {
                      if(command[2]==this.connection.irc.password) {
                        this.connection.irc.password=command[3];
                        this.write(":*jbnc NOTICE * :Password changed to "+command[3]+"\n");
                      }
                      else {
                        this.write(":*jbnc NOTICE * :Incorrect password.\n");
                      }
                    }
                    else {
                      this.write(":*jbnc NOTICE * :Syntax error.\n");
                    }
                    break;
                  default:
                    this.write(":*jbnc NOTICE * :Unknown command.\n");
                    break;
                }
              }
              break;
            default:
              this.connection.write(input[i].toString() + "\n");
              for(m=0;m<this.connection.parents.length;m++) {
                if(this.connection.parents[m]==this)
                  continue;
                else
                  this.connection.parents[m].write(":"+this.connection.irc.nick+" "+input[i].toString() + "\n");
              }
              break;
          }
        }
      }
      else {
        this.end();
      }
    }
  });
  socket.on('close', function() {
    if(this.connection && this.connection.buffers) {
      for(y=0;y<this.connection.buffers.length;y++) {
        if(this.connection.buffers[y].name==this.irc.buffer) {
          this.connection.buffers[y].connected=false;
          break;
        }
      }
      for(i=0;i<this.connection.parents.length;i++) {
        if(this.connection.parents[i]==this)
          break;
      }
      this.connection.parents.splice(i,1);
      if(this.connection.parents.length==0) {
        this.connection.irc.connected=false;
        this.connection.write("AWAY :jbnc\n");
      }
    }
    this.destroy();
  });
  socket.on('error', function(err) {
    console.log(err);
  });
});

// IRC Client
async function clientReconnect(socket,c) {
  socket.connection=connections[c];
  socket.connection.parents[socket.connection.parents.length] = socket;
  socket.irc.connected=true;
  socket.connection.irc.reconnecting = true;
  socket.connection.irc.connected=true;
  for(x=0;x<socket.connection.buffers.length;x++) {
    if(socket.connection.buffers[x].name==socket.irc.buffer) {
      socket.connection.buffers[x].connected=true;
      break;
    }
  }
  if(x==socket.connection.buffers.length) {
    socket.connection.buffers[x]={name:socket.irc.buffer,data:'',connected:true};
  }
  socket.write(socket.connection.connectbuf+"\n");
  if(socket.connection.irc.nick!=socket.connection.irc.nick_original) {
    socket.write(":"+socket.connection.irc.namechange+" NICK "+socket.connection.irc.nick+"\n");
  }
  await socket.connection.write("AWAY\n");
  await socket.connection.write("LUSERS\n");
  await socket.connection.write("MOTD"+"\n");
  await socket.connection.write("MODE "+socket.connection.irc.nick+"\n");
  await socket.connection.write("WHOIS "+socket.connection.irc.nick+"\n");
}

async function clientConnect(socket) {
  let success=true;
  connector=net.createConnection;
  if(socket.irc.port.toString().substr(0,1)=="+") {
    connector=tls.connect;
    socket.irc.port=parseInt(socket.irc.port.toString().substr(1));
  }
  try {
    socket.connection = connector(socket.irc.port, socket.irc.server);
  } catch(e) {
    success=false;
  }
  if(success) {
    socket.connection.parents = [];
    socket.connection.parents[0] = socket;
    socket.connection.buffers = [];
    socket.connection.buffers[0] = {name:socket.irc.buffer,data:'',connected:true};
    socket.irc.connected=true;
    socket.connection.irc = socket.irc;
    socket.connection.buffer='';
    socket.connection.connectbuf='';
    socket.connection.on('connect',function() {
      this.irc.connected=true;
      this.write('NICK '+this.irc.nick+'\n');
      this.write('USER '+this.irc.user+' localhost '+this.irc.server+' :'+this.irc.realname+'\n');
      this.irc.nick_original=this.irc.nick;
    });
    socket.connection.on('data', async function(d){
      if(d.toString().substr(d.length-1)!="\n")
        this.buffer+=d.toString();
      else {
        _d = this.buffer + d.toString();
        this.buffer='';
        lines= _d.split("\n");
        for(n=0;n<lines.length;n++) {
          data = lines[n].split(" ");
          switch(data[1]) {
            case '001':
              if(!this.irc.authenticated) {
                this.irc.authenticated=true;
                this.irc.namechange=data[2];
                connections[connections.length] = this;
              }
            case '002':
            case '003':
            case '004':
            case '005':
              this.connectbuf+=lines[n]+"\n";
              break;
            case '319':
              if(this.irc.reconnecting) {

                if(data[2]==this.irc.nick) {
                  for(x=4;x<data.length;x++) {
                    if(data[x].length>1) {
                      for(t=0;t<this.parents.length;t++) {
                        await this.parents[t].write(":"+this.irc.nick+"!"+this.irc.user+"@jbnc JOIN "+data[x].substr(data[x].indexOf("#"))+"\n");
                      }
                      await this.write("NAMES "+data[x].substr(data[x].indexOf("#"))+"\n");
                      await this.write("MODE "+data[x].substr(data[x].indexOf("#"))+"\n");
                      await this.write("TOPIC "+data[x].substr(data[x].indexOf("#"))+"\n");
                    }
                  }
                  for(t=0;t<this.parents.length;t++) {
                    // read clientbuf if connected
                    for(y=0;y<this.buffers.length;y++) {
                      if(this.parents[t].irc.buffer==this.buffers[y].name && this.buffers[y].connected) {
                        this.parents[t].write(this.buffers[y].data);
                        this.buffers[y].data='';
                      }
                    }
                  }
                }
                this.irc.reconnecting=false;
              }
              break;
            case 'NICK':
              if(data[0].substr(1).split("!")[0]==this.irc.nick) {
                this.irc.nick=data[2].substr(1).trim();
              }
              break;
            case '433':
              if(data[2]=='*') {
                this.write("NICK "+data[3]+"_"+"\n");
                this.irc.nick=data[3]+"_";
              }
              break;
          }
//          if(!this.irc.connected) {
            if(data[0] == "PING")
              this.write("PONG "+data[1].substr(1)+"\n");
//          }
          else {
            for(m=0;m<this.parents.length;m++)
              this.parents[m].write(lines[n]+"\n");
          }
          // store clientbuf if not connected
          if(lines[n].indexOf("PRIVMSG")>0) {
            for(y=0;y<this.buffers.length;y++) {
              if(!this.buffers[y].connected) {
                this.buffers[y].data+=lines[n]+"\n";
              }
            }
          }
        }
      }
    });
    socket.connection.on('close', function() {
      c = getConnection(this.irc)
      connections.splice(c,1);
      for(z=0;z<this.parents.length;z++) {
        this.parents[z].end();
      }
      this.buffers=false;
      this.destroy();
    });
  }
  else
    socket.end();
}

