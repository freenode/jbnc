/*global global, module*/
/*eslint no-undef: "error"*/

class ClientReconnect {
  constructor(socket, client) {
    this.connections = client.connections;
    this.connection = null;
    this.init(socket);
  }

  init(socket) {
    /*let _success = true;
    if (socket.connected)
      _success = false;*/
    if (true) {
      this.connection = this.connections[socket.hash];
      this.connection.parents[this.connection.parents.length] = socket;
      clearTimeout(this.connection.gone);
      this.connection.gone='';
      this.connection.goneTime='';
      socket.connected = true;
      let newdevice = false;
      if (!this.connection.buffers[socket.clientbuffer]) {
        this.connection.buffers[socket.clientbuffer] = { data: '', connected: true, privmsgnotice: [] };
        newdevice = true;
      }
      else
        this.connection.buffers[socket.clientbuffer].connected = true;
      this.write(socket, this.connection.connectbuf + "\n");

      if (this.connection.nick != socket.irc.nick)
        this.write(socket, ":" + this.connection.nick_original + " NICK " + this.connection.nick + "\n");

      if (this.connection.ircv3Monitor)
        this.write(this.connection, "MONITOR S\n");

      if (!this.connection.connected) {
        this.write(this.connection, "AWAY\n");
        this.connection.connected = true;
      }
      if (newdevice) {
        this.write(this.connection, "LUSERS\n");
        this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :Attaching you to the network\n");
        this.write(socket, this.connection.motd + "\n");
        this.write(socket, ":*jbnc 376 " + this.connection.nick + " :End of /MOTD command.\n");
      } else {
        this.connection.users++;
        this.connection.sessionConnections++;
      }

      this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :Attaching you to the network\n");

      // Loop thru channels and send JOINs
      for (let key in this.connection.channels) {
        if (Object.prototype.hasOwnProperty.call(this.connection.channels, key)) {
          let _channel = this.connection.channels[key];

          if (_channel && _channel.name) {
            if (this.connection.ircv3_extendedjoin)
              this.write(socket, "@time=" + new Date().toISOString() + ";msgid=back :" + this.connection.nick + "!" + this.connection.ircuser + "@" + this.connection.host + " JOIN " + _channel.name + " " + (this.connection.account ? this.connection.account : '*') + " :" + this.connection.realname + "\n");
            else
              this.write(socket, "@time=" + new Date().toISOString() + ";msgid=back :" + this.connection.nick + "!" + this.connection.ircuser + "@" + this.connection.host + " JOIN :" + _channel.name + "\n");
          } else {
            console.error(`${parseInt(Number(new Date()) / 1000)}  Probleme bug undefined on join : ${JSON.stringify(_channel)}`);
            //socket.write(`PRIVMSG #!bug-log! Bug du undefined on join - ${_channel.name}\n`);
            continue;
          }


          let _mode_params = '';

          if (typeof _channel.modes === 'undefined')
            _channel.modes = "";

          if (typeof _channel.topic === 'undefined')
            _channel.topic = "";

          for (let x = 0; x < _channel.modes.length; x++) {
            switch (_channel.modes[x]) {
              case 'k': _mode_params += ' ' + _channel.key;
                break;
              case 'j': _mode_params += ' ' + _channel.throttle;
                break;
              case 'l': _mode_params += ' ' + _channel.limit;
                break;
              case 'f': _mode_params += ' ' + _channel.forward;
                break;

              default:
                break;
            }
          }
          this.write(socket, ":*jbnc 324 " + this.connection.nick + " " + key + " +" + _channel.modes + " " + _mode_params + "\n");
          if (_channel.topic.length > 0) {
            this.write(socket, ":*jbnc 332 " + this.connection.nick + " " + key + " :" + _channel.topic + "\n");
            this.write(socket, ":*jbnc 333 " + this.connection.nick + " " + key + " " + _channel.topic_set + " " + _channel.topic_time + "\n");
          }
          if (global.DEBUG) {
            console.log(":*jbnc 324 " + this.connection.nick + " " + key + " +" + _channel.modes + " " + _mode_params);
            if (_channel.topic.length > 0) {
              console.log(":*jbnc 332 " + this.connection.nick + " " + key + " :" + _channel.topic);
              console.log(":*jbnc 333 " + this.connection.nick + " " + key + " " + _channel.topic_set + " " + _channel.topic_time);
            }
          }

          for (let x = 0; x < _channel.names.length; x++) {
            if (x % 53 == 0) {
              this.write(socket, "\n");
              this.write(socket, ":*jbnc 353 " + this.connection.nick + " = " + key + " :");
              if (global.DEBUG)
                console.log(":*jbnc 353 " + this.connection.nick + " = " + key + " :");
            }
            this.write(socket, _channel.names[x]);
            if (global.DEBUG)
              console.log(_channel.names[x]);
            if (x + 1 < _channel.names.length) {
              this.write(socket, " ");
            }
          }
          if (global.DEBUG)
            console.log("\n:*jbnc 366 " + this.connection.nick + " " + key + " :End of /NAMES list.\n");
          this.write(socket, "\n:*jbnc 366 " + this.connection.nick + " " + key + " :End of /NAMES list.\n");

          if (this.connection.vhost)
            this.write(socket, "\n:*jbnc 396 " + this.connection.nick + " " + this.connection.vhost + " :is now your displayed host\n");
        }
      }

      this.write(socket, ":" + this.connection.nick + " MODE " + this.connection.nick + " :+" + this.connection.umode + "\n");
      if (global.DEBUG)
        console.log(":" + this.connection.nick + " MODE " + this.connection.nick + " :+" + this.connection.umode);

      if (global.MSG_REDISTRIBUTION && this.connection.messagetags && this.connection.buffers[socket.clientbuffer] && this.connection.buffers[socket.clientbuffer].privmsgnotice && this.connection.buffers[socket.clientbuffer].privmsgnotice.length > 0) {
        this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :Retrieving all privmsgs/notices\n");
        for (let x = 0; x < this.connection.buffers[socket.clientbuffer].privmsgnotice.length; x++) {
          this.write(socket, this.connection.buffers[socket.clientbuffer].privmsgnotice[x].line);
        }
        this.connection.buffers[socket.clientbuffer].privmsgnotice.length = 0;
        this.write(socket, `:*jbnc PRIVMSG ${this.connection.nick} :End of retrieving all privmsgs/notices\n`);
      }
      else if (!global.MSG_REDISTRIBUTION && this.connection.buffers[socket.clientbuffer] && this.connection.buffers[socket.clientbuffer].data && this.connection.buffers[socket.clientbuffer].data.length > 0) {
        this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :Retrieving all messages\n");
        this.write(socket, this.connection.buffers[socket.clientbuffer].data + "\n");
        this.connection.buffers[socket.clientbuffer].data = '';
        this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :End of retrieving all messages\n");
      }
      else
        this.write(socket, ":*jbnc PRIVMSG " + this.connection.nick + " :There is no new message\n");

      if (this.connection.buffers[socket.clientbuffer] && this.connection.buffers[socket.clientbuffer].data && this.connection.buffers[socket.clientbuffer].data.length > 0) {
        this.connection.buffers[socket.clientbuffer].data = '';
      }
    }
  }

  write(type, line) {
    type.write(line);
  }
}

module.exports = ClientReconnect;
