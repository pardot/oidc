function enrollPublicKey(publicKeyCredential) {
  var req = new XMLHttpRequest();
  req.open("POST", "/EnrollPublicKey", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      console.log("Successful");
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential enroll failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential enroll failed");
  };

  req.send(jsonifyPublicKey(publicKeyCredential));
}

function jsonifyPublicKey(publicKeyCredential) {
  return JSON.stringify({
    id: publicKeyCredential.id,
    rawId: abtob(publicKeyCredential.rawId),
    type: publicKeyCredential.type,
    response: {
      clientDataJSON: abtob(publicKeyCredential.response.clientDataJSON),
      attestationObject: abtob(publicKeyCredential.response.attestationObject)
    }
  })
}

function attemptGetCredential() {
  var req = new XMLHttpRequest();
  req.open("POST", "/CreateCredentialRequestOptions", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialRequestOptions = req.response;
      publicKeyCredentialRequestOptions.challenge = Uint8Array.from(atob(publicKeyCredentialRequestOptions.challenge), c => c.charCodeAt(0));

      navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      }).then(function(publicKeyCredential) {
        console.log(publicKeyCredential);
      }).catch(function(err) {
        // TODO
        console.log("Credential get failed");
        console.log(err);
      });
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential get failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential get failed");
  };

  req.send(JSON.stringify({}));
}

function attemptRegistration() {
  var req = new XMLHttpRequest();
  req.open("POST", "/CreateCredentialCreationOptions", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialCreationOptions = req.response;
      publicKeyCredentialCreationOptions.challenge = Uint8Array.from(atob(publicKeyCredentialCreationOptions.challenge), c => c.charCodeAt(0));
      publicKeyCredentialCreationOptions.user.id = Uint8Array.from(atob(publicKeyCredentialCreationOptions.user.id), c => c.charCodeAt(0));

      navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      }).then(function(publicKeyCredential) {
        enrollPublicKey(publicKeyCredential)
        console.log(publicKeyCredential);
      }).catch(function(err) {
        // TODO
        console.log("Credential creation failed");
        console.log(err);
      });
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential creation failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential creation failed");
  };

  req.send(JSON.stringify({}));
}

function initiateAuthn(e) {
  e.preventDefault();
  attemptGetCredential()
}

function initiateRegistration(e) {
  e.preventDefault();
  attemptRegistration();
}

ready(function() {
  var ele = document.getElementById("authnForm");
  if (ele) {
    ele.addEventListener("submit", initiateAuthn);
  }

  var ele = document.getElementById("registrationLink");
  if (ele) {
    ele.addEventListener("click", initiateRegistration);
  }
});
