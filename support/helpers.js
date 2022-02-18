const { InvalidClientAuth } = require("oidc-provider/lib/helpers/errors");

const revoked = (serialNumber) => {
  return false;
}

function certificateAuthorized(ctx) {
  
  console.info(`certificateAuthorized called`);
  // `ca` chain provided when setting up https server in index.js could verify the cert
  // ctx.socket.authorized already takes care of expired certificate check
  // implement CRL check here
  return ctx.socket.authorized && !revoked(ctx.socket.getPeerCertificate().serialNumber)
}

function certificateSubjectMatches(ctx, property, expected) {
  console.info(`certificateSubjectMatches called: ${expected}`);
  switch (property) {
    case 'tls_client_auth_san_email':
      return ctx.get('x-ssl-client-s-email') === expected;
    default:
      throw new InvalidClientAuth(`${property} certificate subject matching not implemented`);
  }
}

function getCertificate(ctx) {
  console.info('getCertificate called');
  try{
    const peerCertificate = ctx.socket.getPeerCertificate();
    if (peerCertificate.raw) {
      console.info('got certificate');
      const headers = ctx.req.headers;
      //ctx.req.headers = { ... headers, 'x-ssl-client-s-email': peerCertificate.subject.emailAddress}; //openssl cert
      ctx.req.headers = { ... headers, 'x-ssl-client-s-email': peerCertificate.subject.CN}; // step-ca cert
      return `-----BEGIN CERTIFICATE-----\n${peerCertificate.raw.toString('base64')}\n-----END CERTIFICATE-----`;
    }
  }catch(error) {
    console.log(`${error} from ${JSON.stringify(ctx.socket)} or ${JSON.stringify(ctx.req.socket)}`);
    throw new InvalidClientAuth(`${error}:unable to get certificate`);
  }
}

async function renderError(ctx, out, error) {
    //shouldChange('renderError', 'customize the look of the error page');
    ctx.type = 'html';
    ctx.body = `<!DOCTYPE html>
      <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta charset="utf-8">
        <title>oops! something went wrong</title>
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <style>
          @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1{font-weight:100;text-align:center;font-size:2.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}pre{white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:-pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word;margin:0 0 0 1em;text-indent:-1em}
        </style>
      </head>
      <body>
        <div class="container">
          <h1>oops! something went wrong</h1>
          ${Object.entries(out).map(([key, value]) => `<pre><strong>${key}</strong>: ${htmlSafe(value)}</pre>`).join('')}
        </div>
      </body>
      </html>`;
  }

  function getDefaults() {
      const defaults = {
          renderError,
          certificateAuthorized,
          certificateSubjectMatches,
          getCertificate
      };
      return defaults;
  }

  module.exports = getDefaults;