# Demo code on pretty printing in OpenSAML 4
This code shows a how to pretty print a SAML object in OpenSAML 4. This can be very useful for troubleshooting problems in you OpenSAML code.

The code is explained with more detail and background on [this blog post](https://blog.samlsecurity.com/post/prettyprint-opensaml/?utm_source=github&utm_medium=link&utm_campaign=prettyprint&utm_id=prettyprint&utm_content=prettyprint)

The code shows:
* All dependecied needed
* Initializing OpenSAML
* Creating and printing a simple object using OpenSAML 4

## Running the code
Clone this repo, navigate to the folder for this sample and run: 
```
mvn compile exec:java -Dexec.mainClass="no.steras.opensamlSamples.prettyprint.Prettyprint"
 
```
