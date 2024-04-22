// jbnc v0.9.0
// Copyright (C) 2020 Andrew Lee <andrew@imperialfamily.com>
// All Rights Reserved.
const fs = require('fs');

// Load jbnc.conf
let _config = process.argv[2] ? process.argv[2] : "jbnc.conf";
let config = {};
if (fs.existsSync(_config)) {
  config = JSON.parse(fs.readFileSync(_config));
}
else {
  console.error(`No config file found: ${_config}`);
  process.exit(1);
}

// Set config vars
global.BOUNCER_PORT = config.bouncerPort ? config.bouncerPort : 8888;
global.BOUNCER_IP = config.bouncerIp ? config.bouncerIp : null;
global.BOUNCER_USER = config.bouncerUser ? config.bouncerUser : '';
global.BOUNCER_PASSWORD = config.bouncerPassword ? config.bouncerPassword : '';
global.BOUNCER_ADMIN = config.bouncerAdmin ? config.bouncerAdmin : '';
global.BOUNCER_DEFAULT_OPMODE = config.bouncerDefaultOpmode ? config.bouncerDefaultOpmode : false;
global.BOUNCER_MODE = config.mode ? config.mode : 'bouncer';
global.BOUNCER_TIMEOUT = config.bouncerTimeout ? config.bouncerTimeout : 0;
global.BUFFER_MAXSIZE = config.bufferMaxSize ? config.bufferMaxSize : 52428800;
global.BUFFER_LINEMAX = config.lineMax ? config.lineMax : 1500;
global.BOUNCER_SHACK = config.bouncerShack ? config.bouncerShack : 10;
global.SERVER_WEBIRC = config.webircPassword ? config.webircPassword : '';
global.SERVER_WEBIRCHASHIP = config.webircHashIp ? true : false;
global.SERVER_WEBIRCPROXY = config.webircProxy ? true : false;
global.SERVER_TLS_KEY = config.tlsKey ? config.tlsKey : 'privkey.pem';
global.SERVER_TLS_CERT = config.tlsCert ? config.tlsCert : 'fullchain.pem';
global.SERVER_PORT = global.BOUNCER_MODE == 'gateway' ? (config.serverPort ? config.serverPort : 0) : 0;
global.INGRESSWEBIRC = config.ingresswebircPassword ? config.ingresswebircPassword : '';
global.SERVER = global.BOUNCER_MODE == 'gateway' ? (config.server ? config.server : '') : '';
global.MSG_REDISTRIBUTION = config.MsgRedistribution ? true : false;
global.DEBUG = config.debug ? config.debug : false;
global.WEBIRCSPECIAL = config.webircSpecial ? config.webircSpecial : false;
global.IRC_STANDARDS = config.ircStandards ? config.ircStandards : true;
global.UNCAUGHTEXCEPTION = config.uncaughtException ? config.uncaughtException : true;

global.ircCommandList = new Set(["JOIN", "PART", "QUIT", "MODE", "PING", "NICK", "KICK"]);
global.ircCommandRedistributeMessagesOnConnect = new Set(["AWAY", "NICK", "ACCOUNT", "PART", "QUIT", "MODE", "KICK", "TOPIC"]);


// Reload passwords on sighup
process.on('SIGHUP', function () {
  if (fs.existsSync(_config))
    config = JSON.parse(fs.readFileSync(_config));
  else
    process.exit(1);

  global.BOUNCER_PASSWORD = config.bouncerPassword ? config.bouncerPassword : '';
  global.BOUNCER_ADMIN = config.bouncerAdmin ? config.bouncerAdmin : '';
});

if (global.UNCAUGHTEXCEPTION) {
  // Prevent BNC from crashing for all other users when an error is caused by a user (with log error and time)
  process.on('uncaughtException', (err, origin) => {
    console.error(`${parseInt(Number(new Date()) / 1000)} # Serious problem (${origin}) - this should not happen but the JBNC is still running. ${err.stack}`);
  });
}

const jBNC = require('./lib/Server');

const server = new jBNC();
server.listen();
