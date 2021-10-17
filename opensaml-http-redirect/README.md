# Demo code on HTTP Redirect in OpenSAML 4
This code shows a how to use the HTTPRedirectDeflateEncoder and HTTPRedirectDeflateDecoder in OpenSMAL 4 to send a receive messages using HTTP Redirect binding.

The code is explained with more detail and backgound on [this blog post](https://blog.samlsecurity.com/2011/01/redirect-with-authnrequest.html?utm_source=github&utm_medium=link&utm_campaign=opensaml_samples_collection&utm_content=http-redirect-binding)

The demo sets up two servlets acting as different sender and reciever of the a message.

The code shows:
* All dependecied needed
* Initializing OpenSAML
* Sending and receiving messages using OpenSAML 4

## Runing the code
Clone this repo, navigate to the folder for this sample and run: 
```
mvn tomcat:run
```

Then open a browser and navigate to http://localhost:8080/opensaml-http-redirect/redirectPage
All SAML messages used during the communication are logged to the console.
