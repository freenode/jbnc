const http = require('http');
const express = require('express');
const session = require('express-session');

class WebAdminPanel {
  constructor(port, connections, instanceConnections) {
    this.port = port;
    this.connections = connections;
    this.instanceConnections = instanceConnections;
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

    this.app.get('/send', (req, res) => {
      const command = req.query.command;
      if (req.session.authenticated) {
        if (command === 'kill') {
          const key = req.query.key;
          let disconnected = this.instanceConnections.userKill(key);
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