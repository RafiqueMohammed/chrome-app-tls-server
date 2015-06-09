var crlf = "\r\n";

module.exports = "HTTP/1.1 200 OK" + crlf +
new Date().toString() + crlf +
"Content-Type: text/html" + crlf +
"Content-Length: 58" + crlf +
"Access-Control-Allow-Origin: *" + crlf +
"Connection: close" + crlf +
crlf +
"<!doctype html><html><head></head><body>hi</body></html>" + crlf;
