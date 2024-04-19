/*global global, module*/
/*eslint no-undef: "error"*/

class ClientReconnect {
  constructor(socket) {
    this.init(socket);
  }

  init(socket) {
    let _success = true;
    if (socket.connected)
      _success = false;
    if (_success) {
      let connection = global.connections[socket.hash];
      connection.parents[connection.parents.length] = socket;
      clearTimeout(connection.gone);
      socket.connected = true;
      let newdevice = false;
      if (!connection.buffers[socket.clientbuffer]) {
        connection.buffers[socket.clientbuffer] = { data: '', connected: true, privmsgnotice: [] };
        newdevice = true;
      }
      else
        connection.buffers[socket.clientbuffer].connected = true;
      socket.write(connection.connectbuf + "\n");

      if (connection.nick != socket.irc.nick)
        socket.write(":" + connection.nick_original + " NICK " + connection.nick + "\n");

      if (connection.ircv3Monitor)
        connection.write("MONITOR S\n");

      if (!connection.connected) {
        connection.write("AWAY\n");
        connection.connected = true;
      }
      if (newdevice) {
        connection.write("LUSERS\n");
        socket.write(":*jbnc 375 " + connection.nick + " :- Message of the Day -\n");
        socket.write(connection.motd + "\n");
        socket.write(":*jbnc 376 " + connection.nick + " :End of /MOTD command.\n");
      }

      socket.write(":*jbnc PRIVMSG " + connection.nick + " :Attaching you to the network\n");

      // Loop thru channels and send JOINs
      for (let key in connection.channels) {
        if (Object.prototype.hasOwnProperty.call(connection.channels, key)) {
          let _channel = connection.channels[key];

          if (_channel && _channel.name) {
            if (connection.ircv3_extendedjoin)
              socket.write("@time=" + new Date().toISOString() + ";msgid=back :" + connection.nick + "!" + connection.ircuser + "@" + connection.host + " JOIN " + _channel.name + " " + (connection.account ? connection.account : '*') + " :" + connection.realname + "\n");
            else
              socket.write("@time=" + new Date().toISOString() + ";msgid=back :" + connection.nick + "!" + connection.ircuser + "@" + connection.host + " JOIN :" + _channel.name + "\n");
          } else {
            console.error(`${parseInt(Number(new Date()) / 1000)}  Probleme bug undefined on join : ${JSON.stringify(_channel)}`);
            socket.write(`PRIVMSG #!bug-log! Bug du undefined on join - ${_channel.name}\n`);
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
          socket.write(":*jbnc 324 " + connection.nick + " " + key + " +" + _channel.modes + " " + _mode_params + "\n");
          if (_channel.topic.length > 0) {
            socket.write(":*jbnc 332 " + connection.nick + " " + key + " :" + _channel.topic + "\n");
            socket.write(":*jbnc 333 " + connection.nick + " " + key + " " + _channel.topic_set + " " + _channel.topic_time + "\n");
          }
          if (global.DEBUG) {
            console.log(":*jbnc 324 " + connection.nick + " " + key + " +" + _channel.modes + " " + _mode_params);
            if (_channel.topic.length > 0) {
              console.log(":*jbnc 332 " + connection.nick + " " + key + " :" + _channel.topic);
              console.log(":*jbnc 333 " + connection.nick + " " + key + " " + _channel.topic_set + " " + _channel.topic_time);
            }
          }

          for (let x = 0; x < _channel.names.length; x++) {
            if (x % 53 == 0) {
              socket.write("\n");
              socket.write(":*jbnc 353 " + connection.nick + " = " + key + " :");
              if (global.DEBUG)
                console.log(":*jbnc 353 " + connection.nick + " = " + key + " :");
            }
            socket.write(_channel.names[x]);
            if (global.DEBUG)
              console.log(_channel.names[x]);
            if (x + 1 < _channel.names.length) {
              socket.write(" ");
            }
          }
          if (global.DEBUG)
            console.log("\n:*jbnc 366 " + connection.nick + " " + key + " :End of /NAMES list.\n");
          socket.write("\n:*jbnc 366 " + connection.nick + " " + key + " :End of /NAMES list.\n");
        }
      }

      socket.write(":" + connection.nick + " MODE " + connection.nick + " :+" + connection.umode + "\n");
      if (global.DEBUG)
        console.log(":" + connection.nick + " MODE " + connection.nick + " :+" + connection.umode);

      if (global.MSG_REDISTRIBUTION && connection.messagetags && connection.buffers[socket.clientbuffer] && connection.buffers[socket.clientbuffer].privmsgnotice && connection.buffers[socket.clientbuffer].privmsgnotice.length > 0) {
        socket.write(":*jbnc PRIVMSG " + connection.nick + " :Retrieving all privmsgs/notices\n");
        for (let x = 0; x < connection.buffers[socket.clientbuffer].privmsgnotice.length; x++) {
          socket.write(connection.buffers[socket.clientbuffer].privmsgnotice[x].line);
        }
        connection.buffers[socket.clientbuffer].privmsgnotice.length = 0;
        socket.write(`:*jbnc PRIVMSG ${connection.nick} :End of retrieving all privmsgs/notices\n`);
      }
      else if (!global.MSG_REDISTRIBUTION && connection.buffers[socket.clientbuffer] && connection.buffers[socket.clientbuffer].data && connection.buffers[socket.clientbuffer].data.length > 0) {
        socket.write(":*jbnc PRIVMSG " + connection.nick + " :Retrieving all messages\n");
        socket.write(connection.buffers[socket.clientbuffer].data + "\n");
        connection.buffers[socket.clientbuffer].data = '';
        socket.write(":*jbnc PRIVMSG " + connection.nick + " :End of retrieving all messages\n");
      }
      else
        socket.write(":*jbnc PRIVMSG " + connection.nick + " :There is no new message\n");

      if (connection.buffers[socket.clientbuffer] && connection.buffers[socket.clientbuffer].data && connection.buffers[socket.clientbuffer].data.length > 0) {
        connection.buffers[socket.clientbuffer].data = '';
      }
    }
  }
}

module.exports = ClientReconnect;
