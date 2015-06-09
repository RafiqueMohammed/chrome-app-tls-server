var fs = require("fs");
var privateKey = fs.readFileSync(__dirname + "/server.key", "utf8");
var certificate = fs.readFileSync(__dirname + "/server.crt", "utf8");
var responseText = require("./response-text.js");

module.exports = function createTLSConnection(clientId, networkHandlers) {
  var textBuffer = "", responseComplete = false;

  return forge.tls.createConnection({
    server: true,
    caStore: [],
    sessionCache: {},
    sessionId: clientId,
    verifyClient: false,
    verify: function(c, verified, depth, certs) {return true;},
    connected: function(connection) {
      console.log('connected');
    },
    getCertificate: function(c, hint) {
      return certificate;
    },
    getPrivateKey: function(c, cert) {
      return privateKey;
    },
    tlsDataReady: function(connection) {
      networkHandlers.outputHandler(connection, responseComplete);
    },
    dataReady: function(connection) {
      var textData = forge.util.decodeUtf8(connection.data.getBytes());
      textBuffer += textData;

      console.log("TLS decoded client buffer: " + textData);

      if (textBuffer.indexOf("\r\n\r\n") > -1) {
        console.log("Preparing response");
        connection.prepare(forge.util.encodeUtf8(responseText));
        responseComplete = true;
      }
    },
    closed: function(connection) {
      console.log('disconnected');
      networkHandlers.disconnectHandler(connection.sessionId);
    },
    error: function(connection, error) {
      console.log('uh oh' +  error.message);
      connection.close();
      chrome.sockets.tcp.disconnect(connection.sessionId);
    }
  });
};
