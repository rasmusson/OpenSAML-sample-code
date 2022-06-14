package no.steras.opensamlSamples.signingVerification;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * Created by Privat on 4/6/14.
 */
public class SenderServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(SenderServlet.class);

	private static final String MESSAGE_RECEIVER_ENDPOINT = "http://localhost:8080/opensaml-signing-and-verification/receiverPage";
	private static final String ASSERTION_CONSUMER_ENDPOINT = "The should be the endpoint that should recieve the result of the authentication";
	private static final String ISSUER = "This should be the sender entityId";
	private static final String KEY_STORE_PASSWORD = "password";
	private static final String KEY_STORE_ENTRY_PASSWORD = "password";
	private static final String KEY_STORE_PATH = "/senderKeystore.jks";
	private static final String ENTITY_ID = "sender.example.com";

	@Override
	public void init() throws ServletException {
		try {
			JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
			javaCryptoValidationInitializer.init();

			XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
			ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

			registry.setParserPool(OpenSAMLUtils.getParserPool());

			logger.info("Initializing");
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Initialization failed");
		}
	}

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		Writer w = resp.getWriter();

		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>"
				+ "<body><h1>Click the button to sign a message and send it and validate the signature in the reciever.</h1> <form method=\"POST\">"
				+ "<input type=\"submit\" value=\"Go!\"/>" + "</form>" + "</body>" + "</html>");
	}

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		AuthnRequest authnRequest = buildAuthnRequest();
		try {
			sendMessageUsingPOST(resp, authnRequest);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private AuthnRequest buildAuthnRequest() {
		AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setDestination(MESSAGE_RECEIVER_ENDPOINT);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(ASSERTION_CONSUMER_ENDPOINT);
		authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
		authnRequest.setIssuer(buildIssuer());
		authnRequest.setNameIDPolicy(buildNameIdPolicy());

		return authnRequest;
	}

	private NameIDPolicy buildNameIdPolicy() {
		NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
		nameIDPolicy.setAllowCreate(true);

		nameIDPolicy.setFormat(NameIDType.TRANSIENT);

		return nameIDPolicy;
	}

	private Issuer buildIssuer() {
		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(ISSUER);

		return issuer;
	}

	private KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
		try {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream inputStream = this.getClass().getResourceAsStream(pathToKeyStore);
			keystore.load(inputStream, keyStorePassword.toCharArray());
			inputStream.close();
			return keystore;
		} catch (Exception e) {
			throw new RuntimeException("Something went wrong reading keystore", e);
		}
	}

	private Credential getSenderSigningCredential() throws Exception {
		// Get key store
		KeyStore keystore = readKeystoreFromFile(KEY_STORE_PATH, KEY_STORE_PASSWORD);
		Map<String, String> passwordMap = new HashMap<String, String>();
		passwordMap.put(ENTITY_ID, KEY_STORE_ENTRY_PASSWORD);

		// Create key store resolver
		KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

		// Set criterion to get relevant certificate
		Criterion criterion = new EntityIdCriterion(ENTITY_ID);
		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(criterion);

		// Resolve credential
		return resolver.resolveSingle(criteriaSet);
	}

	private SignatureSigningParameters buildSignatureSigningParameters() throws Exception {
		SignatureSigningParameters signingParameters = new SignatureSigningParameters();
		signingParameters.setSigningCredential(getSenderSigningCredential());
		signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		return signingParameters;
	}

	private void sendMessageUsingPOST(HttpServletResponse httpServletResponse, AuthnRequest authnRequest)
			throws Exception {

		MessageContext context = new MessageContext();

		context.setMessage(authnRequest);

		SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
		bindingContext.setRelayState("teststate");

		SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
		endpointContext.setEndpoint(URLToEndpoint(MESSAGE_RECEIVER_ENDPOINT));

		context.getSubcontext(SecurityParametersContext.class, true)
				.setSignatureSigningParameters(buildSignatureSigningParameters());

		SAMLOutboundProtocolMessageSigningHandler handler = new SAMLOutboundProtocolMessageSigningHandler();
		handler.setSignErrorResponses(false);
		handler.initialize();

		handler.invoke(context);

		VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "classpath");
		velocityEngine.setProperty("classpath.resource.loader.class",
				"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		velocityEngine.init();

		HTTPPostEncoder encoder = new HTTPPostEncoder();

		encoder.setMessageContext(context);
		encoder.setHttpServletResponse(httpServletResponse);
		encoder.setVelocityEngine(velocityEngine);

		try {
			encoder.initialize();
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		}

		logger.info("Sending auto-sumbitting form to receiver with AuthnRequest");
		try {
			encoder.encode();
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private Endpoint URLToEndpoint(String URL) {
		SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(URL);

		return endpoint;
	}
}
