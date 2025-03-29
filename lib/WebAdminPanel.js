const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');

const session = require('express-session');

const doreport = require('../lib/Reports');

function saveSettingsToConfig() {
  const config = {
      bouncerPort: global.BOUNCER_PORT,
      bouncerIp: global.BOUNCER_IP,
      bouncerUser: global.BOUNCER_USER,
      bouncerPassword: global.BOUNCER_PASSWORD,
      bouncerAdmin: global.BOUNCER_ADMIN,
      bouncerDefaultOpmode: global.BOUNCER_DEFAULT_OPMODE,

      // Advanced Settings
      mode: global.BOUNCER_MODE,
      bouncerTimeout: global.BOUNCER_TIMEOUT,
      bufferMaxSize: global.BUFFER_MAXSIZE,
      lineMax: global.BUFFER_LINEMAX,

      // WebIRC Settings
      webircPassword: global.SERVER_WEBIRC,
      webircHashIp: global.SERVER_WEBIRCHASHIP,
      webircProxy: global.SERVER_WEBIRCPROXY,

      // Debugging and Admin Panel
      debug: global.DEBUG,
      WebAdminPanel: global.WEBADMINPANEL,
      WebAdminPanelPort: global.WEBADMINPANEL_PORT,
      purgeReports: global.PURGE_REPORTS,
      uidefaultSaveCfg: global.UI_DEFAULT_SAVE_CFG,

      // Additional settings from the global variables
      bouncerShack: global.BOUNCER_SHACK,
      tlsKey: global.SERVER_TLS_KEY,
      tlsCert: global.SERVER_TLS_CERT,
      serverPort: global.SERVER_PORT,
      ingresswebircPassword: global.INGRESSWEBIRC,
      server: global.SERVER,
      MsgRedistribution: global.MSG_REDISTRIBUTION,
      webircSpecial: global.WEBIRCSPECIAL,
      ircStandards: global.IRC_STANDARDS,
      uncaughtException: global.UNCAUGHTEXCEPTION,
      WebAdminPanelPassword: global.WEBADMINPANEL_PASSWORD,
      WebAdminPanelSecret: global.WEBADMINPANEL_SECRET
  };
  const configString = JSON.stringify(config, null, 2);
  const configPath = global.UI_DEFAULT_SAVECFG;

  try {
      if (global.DEBUG) {
        console.log(`Writing: ${configPath} ${configString}`);
      }
      fs.writeFileSync(configPath, configString, 'utf8');
      if (global.DEBUG) {
        console.log(`Configuration saved to ${configPath}`);
      }
      
      doreport.addReport('settings', `Configuration saved to ${configPath}`);

      return { success: true, message: 'Configuration saved successfully' };
  } catch (error) {
      console.error('Error saving configuration:', error);
      
      doreport.addReport('settings', `Error saving configuration: ${error.message}`);

      return { success: false, message: error.message };
  }
}


class WebAdminPanel {
  constructor(port, connections, instanceConnections, reports) {
    this.port = port;
    this.connections = connections;
    this.instanceConnections = instanceConnections;
    this.reports = reports;
    this.app = express();
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(express.json());
    this.setupMiddleware();
    this.setupRoutes();
    this.setup404Error();
  }

  start() {
    this.server = http.createServer(this.app);
    this.server.listen(this.port, () => {
      console.log(`Server WebPanel started and listening on port http://localhost:${this.port}`);
    });
  }

  setupMiddleware() {
    this.app.use(session({
      secret: global.WEBADMINPANEL_SECRET,
      resave: false,
      saveUninitialized: true
    }));
  }

  setupRoutes() {
    this.app.get('/', (req, res) => {
      res.sendFile(__dirname + '/webadminpanel/login.html');
    });

    this.app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (!!global.WEBADMINPANEL_SECRET && !!global.BOUNCER_ADMIN && !!global.WEBADMINPANEL_PASSWORD && username === global.BOUNCER_ADMIN && password === global.WEBADMINPANEL_PASSWORD) {
        req.session.authenticated = true;
        res.redirect('/dashboard');
      } else {
        res.status(401).send('Incorrect username or password');
      }
    });

    this.app.get('/dashboard', (req, res) => {
      if (req.session.authenticated) {
        res.sendFile(__dirname + '/webadminpanel/dashboard.html');
      } else {
        res.redirect('/');
      }
    });

    this.app.get('/settings.json', (req, res) => {
      if (req.session.authenticated) {
        // Collect all the global settings into a single object
        const settings = {
            // Bouncer Settings
            bouncerPort: global.BOUNCER_PORT,
            bouncerIp: global.BOUNCER_IP,
            bouncerUser: global.BOUNCER_USER,
            bouncerPassword: global.BOUNCER_PASSWORD,
            bouncerAdmin: global.BOUNCER_ADMIN,
            bouncerDefaultOpmode: global.BOUNCER_DEFAULT_OPMODE,
    
            // Advanced Settings
            mode: global.BOUNCER_MODE,
            bouncerTimeout: global.BOUNCER_TIMEOUT,
            bufferMaxSize: global.BUFFER_MAXSIZE,
            lineMax: global.BUFFER_LINEMAX,
    
            // WebIRC Settings
            webircPassword: global.SERVER_WEBIRC,
            webircHashIp: global.SERVER_WEBIRCHASHIP,
            webircProxy: global.SERVER_WEBIRCPROXY,
    
            // Debugging and Admin Panel
            debug: global.DEBUG,
            WebAdminPanel: global.WEBADMINPANEL,
            WebAdminPanelPort: global.WEBADMINPANEL_PORT
        };
    
        res.json(settings);
      } else {
        return res.status(403).send('Access Denied');
      }
    });

    this.app.get('/reports.json', (req, res) => {
      if (req.session.authenticated) {
        const reports = doreport.getReports();
        res.json(reports);
      }
    });

    this.app.get('/connections.json', (req, res) => {
      if (req.session.authenticated) {
        let connectionsData = [];
        for (const key in this.connections) {
          if (Object.hasOwnProperty.call(this.connections, key)) {
            let connection = {
              key: key,
              nick: this.connections[key].nick,
              user: this.connections[key].user,
              host: this.connections[key].host,
              realname: this.connections[key].realname,
              goneTime: this.connections[key].goneTime,
              users: this.connections[key].users,
              sessionConnections: this.connections[key].sessionConnections,
              channelCount: this.instanceConnections.userChannelCount(key)
            };
            connectionsData.push(connection);
          }
        }
        let responseData = {
          connections: connectionsData,
          count: connectionsData.length,
          last_launch: global.LAST_LAUNCH,
          last_bug: global.LAST_BUG
        };
  
        res.json(responseData);
      } else {
        res.redirect('/');
      }

    });

    this.app.get('/clear-reports', (req, res) => {
      // Check if user is authenticated
      if (req.session.authenticated) {
          // Get hours from query parameter
          const hours = parseInt(req.query.hours, 10);
          this.server.clearHours(hours);
      }
    });

    this.app.get('/send', (req, res) => {
      const command = req.query.command;
      if (res.headersSent) {
        console.error('Headers already sent');
        return;
    }
      if (req.session.authenticated) {
        if (global.DEBUG) {
          console.log(`Got command: ${command}`);
        }
        if (command === 'clear') {
          let hours = req.query.hours;
          if (global.DEBUG) {
            console.log(`Clearing hours: ${hours}`);
          }
          clearReports(hours);
          doreport.addReport('reports',`Reports older than ${hours} purged by admin UI.`);
        }
        if (command === 'kill') {
          const key = req.query.key;
          let nick = this.connections[key].nick;
          let disconnected = this.instanceConnections.userKill(key);
          doreport.addReport('clients',`${nick} killed by admin UI.`);
          if(disconnected)
            res.send("disconnected");
          else
            res.send("none disconnected");
        } 
        else {
          res.send("none");
        }
      } else {
        res.redirect('/');
      }

      if (command === 'update_settings') {
        try {
            // Parse the settings from the request
            const newSettings = JSON.parse(req.query.settings);
            // Update global variables based on input
            doreport.addReport('settings','Admin UI updated settings.');
            if (newSettings.bouncerPort !== undefined) global.BOUNCER_PORT = newSettings.bouncerPort;
            if (newSettings.bouncerIp !== undefined) global.BOUNCER_IP = newSettings.bouncerIp;
            if (newSettings.bouncerUser !== undefined) global.BOUNCER_USER = newSettings.bouncerUser;
            if (newSettings.bouncerPassword !== undefined) global.BOUNCER_PASSWORD = newSettings.bouncerPassword;
            if (newSettings.bouncerAdmin !== undefined) global.BOUNCER_ADMIN = newSettings.bouncerAdmin;
            if (newSettings.bouncerDefaultOpmode !== undefined) global.BOUNCER_DEFAULT_OPMODE = newSettings.bouncerDefaultOpmode;
            // Advanced Settings
            if (newSettings.mode !== undefined) global.BOUNCER_MODE = newSettings.mode;
            if (newSettings.bouncerTimeout !== undefined) global.BOUNCER_TIMEOUT = newSettings.bouncerTimeout;
            if (newSettings.bufferMaxSize !== undefined) global.BUFFER_MAXSIZE = newSettings.bufferMaxSize;
            if (newSettings.lineMax !== undefined) global.BUFFER_LINEMAX = newSettings.lineMax;
            // WebIRC Settings
            if (newSettings.webircPassword !== undefined) global.SERVER_WEBIRC = newSettings.webircPassword;
            if (newSettings.webircHashIp !== undefined) global.SERVER_WEBIRCHASHIP = newSettings.webircHashIp;
            if (newSettings.webircProxy !== undefined) global.SERVER_WEBIRCPROXY = newSettings.webircProxy;
            // Debugging and Admin Panel
            if (newSettings.debug !== undefined) global.DEBUG = newSettings.debug;
            if (newSettings.WebAdminPanel !== undefined) global.WEBADMINPANEL = newSettings.WebAdminPanel;
            if (newSettings.WebAdminPanelPort !== undefined) global.WEBADMINPANEL_PORT = newSettings.WebAdminPanelPort;
            const saveResult = saveSettingsToConfig();
            if (saveResult.success) {
              if (global.DEBUG) {
                console.log(`Settings saved.`);
              }
            } else {
              if (global.DEBUG) {
                console.log(`Error saving settings.`);
              }
            }
        } catch (error) {
            console.error('Error updating settings:', error);
        }
    } 
    
    });
  }

  setup404Error() {
    this.app.use((req, res, next) => {
      const errorMessage = "Sorry, the page you are looking for doesn't exist.";
      res.status(404).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Error 404</title>
        </head>
        <body>
          <h1>Error 404</h1>
          <p>${errorMessage}</p>
        </body>
        </html>
      `);
    });
  }
}

module.exports = WebAdminPanel;