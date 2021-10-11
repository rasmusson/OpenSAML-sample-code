# Demo of SP and IdP interacting using OpenSAML 4
This code shows a simulation of how a SP and a IdP might communicate using SAML. Variations on this demo is used exensivley in the books [A Guide to OpenSAML V2](https://payhip.com/b/odEY?utm_source=github&utm_medium=link&utm_campaign=opensaml_samples_collection&utm_content=getting-started-authn) and [A Guide to OpenSAML V3](https://payhip.com/b/41Tw?utm_source=github&utm_medium=link&utm_campaign=opensaml_samples_collection&utm_content=getting-started-authn).

The demo code sets up several servlets acting as different endpoints on SP, IdP and business application.

The demo acts a good overview guide to OpenSAML demonstrating:
* Building, singing and sending a AuthnRequest using HTTP Redirect binding
* Parsing and verifying signatures on AuthnRequest
* Sending a Response message using the Artifact binding
* Encrypting and decryoting a Assertion

## Runing the code
Clone the code, navigate to the folder for this sample and run: 
```
mvn tomcat:run
```

Then open a browser and navigate to http://localhost:8080/opensaml4-webprofile-demo/app/appservlet

All SAML messages used during the communication are logged to the console.
