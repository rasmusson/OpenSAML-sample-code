package no.steras.opensamlSamples.nobootstrap.v4;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class NoBootstrap {
	private static final String MESSAGE_RECEIVER_ENDPOINT = "DUMMY_RECEIVER_ENDPOINT";
	private static final String ASSERTION_CONSUMER_ENDPOINT = "DUMMY_ASSERTION_CONSUMER_ENDPOINT";

	public static void main(String[] args) throws Exception {
		//initOpenSAML();
		AuthnRequest authnRequest = buildAuthnRequest();

		// Pretty print
		Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);
		out.marshall(authnRequest);
		Element element = authnRequest.getDOM();
		String xmlString = SerializeSupport.prettyPrintXML(element);

		System.out.println(xmlString);
	}

	private static void initOpenSAML() throws Exception {
		try {
			XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
			ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Initialization failed");
		}

	}

	private static AuthnRequest buildAuthnRequest() {
		AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setDestination(MESSAGE_RECEIVER_ENDPOINT);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(ASSERTION_CONSUMER_ENDPOINT);
		authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
		authnRequest.setIssuer(null);
		authnRequest.setNameIDPolicy(null);

		return authnRequest;
	}

}
