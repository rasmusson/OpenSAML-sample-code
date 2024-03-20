package no.steras.opensamlSamples.opensaml4WebprofileDemo;

import java.io.StringWriter;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;


/**
 * Created by Privat on 4/6/14.
 */
public class OpenSAMLUtils {
	private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
	private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

	static {
		secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

	}

	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}

		return object;
	}

	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	public static void logSAMLObject(final XMLObject object) {
		
		
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
				&& object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				logger.error(e.getMessage(), e);
			}
		}

		String xmlString = SerializeSupport.prettyPrintXML(element);

		logger.info(xmlString);

	}
	
	public static void logSAMLObjectRaw(final XMLObject object) {
		try {
			TransformerFactory tf = TransformerFactory.newInstance();
		    Transformer transformer;
		    transformer = tf.newTransformer();
	        StringWriter writer = new StringWriter();
	         
	        //transform document to string 
	        transformer.transform(new DOMSource(object.getDOM()), new StreamResult(writer));
	 
	        String xmlTempString = writer.getBuffer().toString(); 
	        logger.info(xmlTempString);   
		}catch(Exception ex) {
			logger.error("logSAMLObjectRaw error: ", ex);
		} 
	}
	
	public static void logSAMLObjectRaw(final Element elem) {
		try {
			TransformerFactory tf = TransformerFactory.newInstance();
		    Transformer transformer;
		    transformer = tf.newTransformer();
	        StringWriter writer = new StringWriter();
	         
	        //transform document to string 
	        transformer.transform(new DOMSource(elem), new StreamResult(writer));
	 
	        String xmlTempString = writer.getBuffer().toString(); 
	        logger.info(xmlTempString);   
		}catch(Exception ex) {
			logger.error("logSAMLObjectRaw error: ", ex);
		} 
	}	
}
