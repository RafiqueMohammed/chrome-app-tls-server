var privateKey = require("./private/key.js"),
    certificate = require("./private/certificate.js"),
    receiveTextBuffers = {}, tlsConnections = {}, closeSignals = {}

crlf = "\r\n",

responseText = "HTTP/1.1 200 OK" + crlf +
new Date().toString() + crlf +
"Content-Type: text/html" + crlf +
"Content-Length: 58" + crlf +
"Access-Control-Allow-Origin: *" + crlf +
"Connection: close" + crlf +
crlf +
"<!doctype html><html><head></head><body>hi</body></html>" + crlf;

chrome.sockets.tcpServer.create({}, function(createInfo) {
    listenAndAccept(createInfo.socketId);
});

function listenAndAccept(socketId) {
  chrome.sockets.tcpServer.listen
  (socketId, "127.0.0.1", 9999, function(resultCode) {
    onListenCallback(socketId, resultCode);
  });
}

function onListenCallback(socketId, resultCode) {
  if (resultCode < 0) {
    console.log("Error listening:" +
        chrome.runtime.lastError.message);
    return;
  }
  chrome.sockets.tcpServer.onAccept.addListener(onAccept);
}

function onAccept(info) {
  var clientId = info.clientSocketId;

  chrome.sockets.tcp.setPaused(clientId, false);
  tlsConnections[clientId] = createTLSConnection(clientId);
  console.log("Accepted socket connection.  TLS Connection started on socket " + clientId);
}

chrome.sockets.tcp.onReceive.addListener(function(recvInfo) {
  var procCount, stringifiedData;

  console.log("received data length " + recvInfo.data.byteLength + " on socket " + recvInfo.socketId);
  stringifiedData = arrayBufferToString(recvInfo.data);

  console.log("processing encrypted data");
  tlsConnections[recvInfo.socketId].process(stringifiedData);
});

function arrayBufferToString(buffer) {
  //var str = new TextDecoder("utf-8", {fatal:true}).decode(buffer);
  //console.log(str);
  //return str;

  var str = '';
  var uArrayVal = new Uint8Array(buffer);
  for (var s = 0; s < uArrayVal.length; s++) {
    str += String.fromCharCode(uArrayVal[s]);
  }
  return str;
}

var stringToUint8Array = function(string) {
  //return new TextEncoder().encode(string);
  var buffer = new ArrayBuffer(string.length);
  var view = new Uint8Array(buffer);
  for (var i = 0; i < string.length; i++) {
    view[i] = string.charCodeAt(i);
  }
  return view;
};

var closeConnections = function(socketId) {
  chrome.sockets.tcp.disconnect(socketId, function() {
    //chrome.sockets.tcp.close(socketId);
    tlsConnections[socketId].close();
    delete tlsConnections.socketId;
    delete receiveTextBuffers.socketId;
  });
};

//var certData = {};
//createCertificate("localhost", certData);

function createTLSConnection(clientSocketId) {
  return forge.tls.createConnection({
    server: true,
    caStore: [],
    sessionCache: {},
    sessionId: clientSocketId,
    verifyClient: false,
    verify: function(c, verified, depth, certs) {return true;},
    connected: function(connection) {
      console.log('connected');
      receiveTextBuffers[connection.sessionId] = "";
    },
    getCertificate: function(c, hint) {
      //return certData.localhost.cert;
      return certificate;
    },
    getPrivateKey: function(c, cert) {
      //return certData.localhost.privateKey;
      return privateKey;
    },
    tlsDataReady: function(connection) {
      sendEncryptedDataToClient(connection.sessionId, connection.tlsData.getBytes());
    },
    dataReady: function(connection) {
      var textData = forge.util.decodeUtf8(connection.data.getBytes());
      receiveTextBuffers[connection.sessionId] += textData;

      console.log("TLS decoded client buffer: " + textData);

      if (receiveTextBuffers[connection.sessionId].indexOf("\r\n\r\n") > -1) {
        console.log("Preparing response");
        connection.prepare(forge.util.encodeUtf8(responseText));
        closeSignals[connection.sessionId] = true;
      }
    },
    closed: function(connection) {
      console.log('disconnected');
      closeConnections(connection.sessionId);
    },
    error: function(connection, error) {
      console.log('uh oh' +  error.message);
      closeConnections(connection.sessionId);
    }
  });
}

function sendEncryptedDataToClient(clientSocketId, bytes, close) {
  chrome.sockets.tcp.getInfo(clientSocketId, function(info) {
    if (!info.connected) {
      console.log("The socket is no longer connected");
      return closeConnections(clientSocketId);
    }

    var buf = stringToUint8Array(bytes);
    console.log("Sending " + buf.byteLength + " encrypted bytes to socket: " + clientSocketId);

    chrome.sockets.tcp.send
    (clientSocketId, buf.buffer, function(sendInfo) {
      console.log("sent encrypted bytes " + JSON.stringify(sendInfo));
      if (closeSignals[clientSocketId]) {closeConnections(clientSocketId);}
    });
  });
}


function createCertificate(cn, data) {
  var keys = forge.pki.rsa.generateKeyPair(512);
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: cn
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Test'
  }, {
    name: 'localityName',
    value: 'Test'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage', 
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 2,
      value: 'localhost'
    }]
  }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  data[cn] = {
    cert: forge.pki.certificateToPem(cert),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey)
  };
}
