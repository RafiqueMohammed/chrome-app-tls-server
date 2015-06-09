(function() {
  var connections = {},
  createTLSConnection = require("./tls-connection.js"),
  networkHandlers = {
    "disconnectHandler": networkDisconnectHandler,
    "outputHandler": networkOutputHandler
  };

  chrome.sockets.tcpServer.create({}, function(createInfo) {
    chrome.sockets.tcpServer.listen
    (createInfo.socketId, "127.0.0.1", 9999, function(resultCode) {
      if (resultCode < 0) {
        return console.log("Error listening:" + chrome.runtime.lastError.message);
      }

      chrome.sockets.tcpServer.onAccept.addListener(onAccept);
    });
  });

  function onAccept(info) {
    var clientId = info.clientSocketId;

    chrome.sockets.tcp.setPaused(clientId, false);
    connections[clientId] = createTLSConnection(clientId, networkHandlers);
    console.log("TLS Connection started on socket " + clientId);
  }

  chrome.sockets.tcp.onReceive.addListener(function(recvInfo) {
    var stringifiedData;

    console.log("received data length " + recvInfo.data.byteLength +
    " on socket " + recvInfo.socketId);

    stringifiedData = arrayBufferToString(recvInfo.data);

    console.log("processing encrypted data through tls");
    if (connections.hasOwnProperty(recvInfo.socketId)) {
      connections[recvInfo.socketId].process(stringifiedData);
    }
  });

  function networkOutputHandler(connection, responseComplete) {
    chrome.sockets.tcp.getInfo(connection.sessionId, function(info) {
      if (!info.connected) {
        console.log("The socket is no longer connected");
        return connection.close;
      }

      var buf = stringToUint8Array(connection.tlsData.getBytes());
      if (buf.byteLength === 0) { return; }

      console.log("Sending " + buf.byteLength + " encrypted bytes to " +
      "socket: " + connection.sessionId);

      chrome.sockets.tcp.send
      (connection.sessionId, buf.buffer, function(sendInfo) {
        console.log("sent encrypted bytes " + JSON.stringify(sendInfo));
        if (responseComplete) {
          connection.close();
          delete connections[connection.socketId];
        }
      });
    });
  }

  function networkDisconnectHandler(socket) {
    chrome.sockets.tcp.disconnect(socket);
    delete connections[socket];
  }

  function arrayBufferToString(buffer) {
    var str = '';
    var uArrayVal = new Uint8Array(buffer);
    for (var s = 0; s < uArrayVal.length; s++) {
      str += String.fromCharCode(uArrayVal[s]);
    }
    return str;
  }

  function stringToUint8Array (string) {
    //return new TextEncoder().encode(string);
    var buffer = new ArrayBuffer(string.length);
    var view = new Uint8Array(buffer);
    for (var i = 0; i < string.length; i++) {
      view[i] = string.charCodeAt(i);
    }
    return view;
  }
}());
