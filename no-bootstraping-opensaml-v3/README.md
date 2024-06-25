# Library not initialized in OpenSAML 3
A simple code sample showing the error that is thrown if the OpenSAML library is not properly initialized. 

[This blog post](https://blog.samlsecurity.com/2014/05/nullpointer-exception-in-opensaml.html/?utm_source=github&utm_medium=link&utm_campaign=no-bootstrap-opensaml&utm_id=no-bootstrap-opensaml&utm_content=no-bootstrap-opensaml) uses the code and explains the problem 


Running the code shows the exception thrown when using the library without initializing it. The code shows the correct way of initializing the library in OpenSAMl version 3

## Running the code
Clone this repo, navigate to the folder for this sample and run: 
```
mvn compile exec:java -Dexec.mainClass="no.steras.opensamlSamples.nobootstrap.v3.NoBootstrap"
 
```
