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

function authenticatePublicKey(publicKeyCredential) {
  var req = new XMLHttpRequest();
  req.open("POST", "/AuthenticatePublicKey", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      console.log("Successful");
    } else {
      // TODO: Do something more user-friendly here
      console.log("Credential authenticate failed");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Credential authenticate failed");
  };

  req.send(jsonifyPublicKey(publicKeyCredential));
}

function attemptAuthentication() {
  var req = new XMLHttpRequest();
  req.open("POST", "/CreateAuthenticateOptions", true);
  req.setRequestHeader("content-type", "application/json");
  req.responseType = "json"
  req.onload = function() {
    if (req.status == 201) {
      var publicKeyCredentialRequestOptions = req.response;
      publicKeyCredentialRequestOptions.challenge = ato8a(publicKeyCredentialRequestOptions.challenge);

      navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      }).then(function(publicKeyCredential) {
        authenticatePublicKey(publicKeyCredential);
      }).catch(function(err) {
        // TODO
        console.log("Getting credentials failed");
        console.log(err);
      });
    } else {
      // TODO: Do something more user-friendly here
      console.log("Create authenticate options request returned non-201");
    }
  };
  req.onerror = function() {
    // TODO: Do something more user-friendly here
    console.log("Create authenticate options request failed");
  };

  req.send(JSON.stringify({}));
}

function attemptEnrollment() {
  var req = new XMLHttpRequest();
  req.open("POST", "/CreateEnrollOptions", true);
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

function jsonifyPublicKey(publicKeyCredential) {
  return JSON.stringify({
    id: publicKeyCredential.id,
    rawId: abtoa(publicKeyCredential.rawId),
    type: publicKeyCredential.type,
    response: {
      clientDataJSON: abtoa(publicKeyCredential.response.clientDataJSON),
      attestationObject: abtoa(publicKeyCredential.response.attestationObject),
      authenticatorData: abtoa(publicKeyCredential.response.authenticatorData),
      signature: abtoa(publicKeyCredential.response.signature),
      userHandle: abtoa(publicKeyCredential.response.userHandle)
    }
  })
}

function initiateAuthn(e) {
  e.preventDefault();
  attemptAuthentication()
}

function initiateRegistration(e) {
  e.preventDefault();
  attemptEnrollment();
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
