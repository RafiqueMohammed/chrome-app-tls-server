var fs = require("fs");
var receiveTextBuffers = {};
var tlsConnections = {};
var serverSideCloseRequests = {};
var privateKey = fs.readFileSync(__dirname + "/server.key", "utf8");
var certificate = fs.readFileSync(__dirname + "/server.crt", "utf8");
var responseText = require("./response-text.js");

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

  console.log("processing encrypted data through tls");
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
    tlsConnections[socketId].close();
    delete tlsConnections.socketId;
    delete receiveTextBuffers.socketId;
    delete serverSideCloseRequests.socketId;
  });
};

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
      return certificate;
    },
    getPrivateKey: function(c, cert) {
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
        serverSideCloseRequests[connection.sessionId] = true;
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
      if (serverSideCloseRequests[clientSocketId]) {closeConnections(clientSocketId);}
    });
  });
}
