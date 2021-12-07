# OpenSAML 4 signing and signature verification demo 
This code shows a complete example of calculating XML signatures and validating them in OpenSAML 4. I also shows how to use surrounding components needed such as credential resolver, message handlers and trust engines.

The code is explained with detail and backgound on [this blog post](https://blog.samlsecurity.com/2012/11/verifying-signatures-with-opensaml?utm_source=github&utm_medium=link&utm_campaign=opensaml_samples_collection&utm_content=opensaml-signing-and-verification)

The demo sets up two servlets acting as sender and reciever of the a message, where the sender uses KeyStoreCredentialResolver and SAMLOutboundProtocolMessageSigningHandler to sign the message. The receiver uses FilesystemMetadataResolver and SAMLProtocolMessageXMLSignatureSecurityHandler to verify the message.

The code shows:
* All dependecied needed
* Use of message handlers for signatures
* Popular credential resolvers
* Sending and receiving messages using OpenSAML 4

## Runing the code
Clone this repo, navigate to the folder for this sample and run: 
```
mvn tomcat:run
```

Then open a browser and navigate to http://localhost:8080/opensaml-signing-and-verification/senderPage
All SAML messages used during the communication are logged to the console.
