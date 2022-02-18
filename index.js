/* eslint-disable no-console */

const dotenv = require('dotenv');

const path = require('path');
const { promisify } = require('util');

const helmet = require('helmet');

const { Provider } = require('oidc-provider');
const configuration = require('./support/configuration');
const fs = require('fs');
const http = require('http');
const https = require('https');

dotenv.config();

const { ISSUER = `http://localhost`, CERTS_DIR = './certs', HTTP_PORT = 8989, HTTPS_PORT = 7979 } = process.env;

let httpServer, httpsServer;

(async () => {
  let adapter;
  if (process.env.MONGODB_URI) {
    adapter = require('./support/mongodb'); // eslint-disable-line global-require
    await adapter.connect();
  }

  const prod = process.env.NODE_ENV === 'production';

  configuration.jwks = {
    keys: JSON.parse(fs.readFileSync(path.resolve(process.cwd(), `${CERTS_DIR}/jwks.json`), 'utf8').toString())
  };

  const provider = new Provider(ISSUER, { adapter, ...configuration });

  const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
  delete directives['form-action'];
  const pHelmet = promisify(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives,
    },
  }));

  provider.use(async (ctx, next) => {
    const origSecure = ctx.req.secure;
    ctx.req.secure = ctx.request.secure;
    await pHelmet(ctx.req, ctx.res);
    ctx.req.secure = origSecure;
    return next();
  });

  if (prod) {
    provider.proxy = true;
    provider.use(async (ctx, next) => {
      if (ctx.secure) {
        await next();
      } else if (ctx.method === 'GET' || ctx.method === 'HEAD') {
        ctx.status = 303;
        ctx.redirect(ctx.href.replace(/^http:\/\//i, 'https://'));
      } else {
        ctx.body = {
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        };
        ctx.status = 400;
      }
    });
  }

  var config = {
    domain: 'localhost',
    http: {
      port: HTTP_PORT,
    },
    https: {
      port: HTTPS_PORT,
      options: {
        key: fs.readFileSync(path.resolve(process.cwd(), `${CERTS_DIR}/server.key`), 'utf8').toString(),
        cert: fs.readFileSync(path.resolve(process.cwd(), `${CERTS_DIR}/server.crt`), 'utf8').toString(),
        requestCert: true,
        rejectUnauthorized: false,
        ca: fs.readFileSync(path.resolve(process.cwd(), `${CERTS_DIR}/root_ca.crt`))
      },
    },
  };

  let serverCallback = provider.app.callback();
try {
  httpServer = http.createServer(serverCallback);
  httpServer
    .listen(config.http.port, function(err) {
      if (!!err) {
        console.error('HTTP server FAIL: ', err, (err && err.stack));
      }
      else {
        console.log(`HTTP  server OK: http://${config.domain}:${config.http.port}`);
      }
    });
}
catch (ex) {
  console.error('Failed to start HTTP server\n', ex, (ex && ex.stack));
}
try {
  httpsServer = https.createServer(config.https.options, serverCallback);
  httpsServer
    .listen(config.https.port, function(err) {
      if (!!err) {
        console.error('HTTPS server FAIL: ', err, (err && err.stack));
      }
      else {
        console.log(`HTTPS server OK: https://${config.domain}:${config.https.port}`);
      }
    });
}
catch (ex) {
  console.error('Failed to start HTTPS server\n', ex, (ex && ex.stack));
}

  function handleClientAuthErrors({ headers: { authorization }, oidc: { body, client } }, err) {
    if (err.statusCode === 401 && err.message === 'invalid_client') {
       console.log(err);
    }
  }
  provider.on('grant.error', handleClientAuthErrors);
  provider.on('introspection.error', handleClientAuthErrors);
  provider.on('revocation.error', handleClientAuthErrors);


})().catch((err) => {
  if (httpServer && httpServer.listening) httpServer.close();
  if (httpsServer && httpsServer.listening) httpsServer.close();
  console.error(err);
  process.exitCode = 1;
});