function ready(fn) {
  if (document.attachEvent ? document.readyState === "complete" : document.readyState !== "loading"){
    fn();
  } else {
    document.addEventListener('DOMContentLoaded', fn);
  }
}

// ArrayBuffer to Base64
function abtoa(buffer) {
  if (!buffer) {
    return null;
  }

  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Base64 to Uint8Array
function ato8a(encodedData) {
  if (!encodedData) {
    return null;
  }

  return Uint8Array.from(atob(encodedData), function(c) { return c.charCodeAt(0); });
}
