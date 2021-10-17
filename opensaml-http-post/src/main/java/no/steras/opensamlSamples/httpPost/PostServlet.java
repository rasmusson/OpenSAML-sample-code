package no.steras.opensamlSamples.httpPost;

import java.io.IOException;
import java.io.Writer;
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
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

/**
 * Created by Privat on 4/6/14.
 */
public class PostServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(PostServlet.class);

	private static final String MESSAGE_RECEIVER_ENDPOINT = "http://localhost:8080/opensaml-http-post/receiverPage";
	private static final String ASSERTION_CONSUMER_ENDPOINT = "The should be the endpoint that should recieve the result of the authentication";
	private static final String ISSUER = "This should be the sender entityId";

	@Override
	public void init() throws ServletException {
		try {
			XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
			ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

			registry.setParserPool(getParserPool());

			logger.info("Initializing");
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Initialization failed");
		}
	}

	private static ParserPool getParserPool() {
		BasicParserPool parserPool = new BasicParserPool();
		parserPool.setMaxPoolSize(100);
		parserPool.setCoalescing(true);
		parserPool.setIgnoreComments(true);
		parserPool.setIgnoreElementContentWhitespace(true);
		parserPool.setNamespaceAware(true);
		parserPool.setExpandEntityReferences(false);
		parserPool.setXincludeAware(false);

		final Map<String, Boolean> features = new HashMap<String, Boolean>();
		features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
		features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
		features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

		parserPool.setBuilderFeatures(features);

		parserPool.setBuilderAttributes(new HashMap<String, Object>());

		try {
			parserPool.initialize();
		} catch (ComponentInitializationException e) {
			logger.error(e.getMessage(), e);
		}

		return parserPool;
	}

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		Writer w = resp.getWriter();

		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>"
				+ "<body><h1>Click the button to send the AuthnRequest using HTTP POST</h1> <form method=\"POST\">"
				+ "<input type=\"submit\" value=\"Send\"/>" + "</form>" + "</body>" + "</html>");
	}

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		AuthnRequest authnRequest = buildAuthnRequest();
		sendMessageUsingPOST(resp, authnRequest);
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

	private void sendMessageUsingPOST(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {

		MessageContext context = new MessageContext();

		context.setMessage(authnRequest);

		SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
		bindingContext.setRelayState("teststate");

		SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
		endpointContext.setEndpoint(URLToEndpoint(MESSAGE_RECEIVER_ENDPOINT));

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
