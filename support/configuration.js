const { certificateAuthorized, certificateSubjectMatches, getCertificate } = require('./helpers')(); // make your own, you'll need it anyway

module.exports = {
    tokenEndpointAuthMethods: [ 
        'tls_client_auth',
        'self_signed_tls_client_auth',
    ],
    grantTypes: ['client_credentials'],
    responseTypes: ['none'],
    features: {
      clientCredentials: {
        enabled: true
      },
      devInteractions: { enabled: false },
      mTLS: {
        certificateAuthorized: certificateAuthorized,
        certificateBoundAccessTokens: false,
        certificateSubjectMatches: certificateSubjectMatches,
        enabled: true,
        getCertificate: getCertificate,
        selfSignedTlsClientAuth: true,
        tlsClientAuth: true
      },
      registration: {
        enabled: true
      }
    }
  };