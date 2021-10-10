package no.steras.opensamlSamples.opensaml4WebprofileDemo.sp;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.OpenSAMLUtils;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.idp.IDPConstants;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.idp.IDPCredentials;

/**
 * Created by Privat on 4/6/14.
 */
public class ConsumerServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(ConsumerServlet.class);

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		logger.info("Artifact received");
		Artifact artifact = buildArtifactFromRequest(req);
		logger.info("Artifact: " + artifact.getArtifact());

		ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
		logger.info("Sending ArtifactResolve");
		logger.info("ArtifactResolve: ");
		OpenSAMLUtils.logSAMLObject(artifactResolve);

		ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve, resp);
		logger.info("ArtifactResponse received");
		logger.info("ArtifactResponse: ");
		OpenSAMLUtils.logSAMLObject(artifactResponse);

		validateDestinationAndLifetime(artifactResponse, req);

		EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
		Assertion assertion = decryptAssertion(encryptedAssertion);
		verifyAssertionSignature(assertion);
		logger.info("Decrypted Assertion: ");
		OpenSAMLUtils.logSAMLObject(assertion);

		logAssertionAttributes(assertion);
		logAuthenticationInstant(assertion);
		logAuthenticationMethod(assertion);

		setAuthenticatedSession(req);
		redirectToGotoURL(req, resp);
	}

	private void validateDestinationAndLifetime(ArtifactResponse artifactResponse, HttpServletRequest request) {
		MessageContext context = new MessageContext();
		context.setMessage(artifactResponse);

		SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
		messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

		MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
		lifetimeSecurityHandler.setClockSkew(Duration.ofMillis(1000));
		lifetimeSecurityHandler.setMessageLifetime(Duration.ofMillis(2000));
		lifetimeSecurityHandler.setRequiredRule(true);

		ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
		receivedEndpointSecurityHandler.setHttpServletRequest(request);
		List handlers = new ArrayList<MessageHandler>();
		handlers.add(lifetimeSecurityHandler);
		handlers.add(receivedEndpointSecurityHandler);

		BasicMessageHandlerChain handlerChain = new BasicMessageHandlerChain();
		handlerChain.setHandlers(handlers);

		try {
			handlerChain.initialize();
			handlerChain.doInvoke(context);
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		} catch (MessageHandlerException e) {
			throw new RuntimeException(e);
		}

	}

	private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
		StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
				SPCredentials.getCredential());

		Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
		decrypter.setRootInNewDocument(true);

		try {
			return decrypter.decrypt(encryptedAssertion);
		} catch (DecryptionException e) {
			throw new RuntimeException(e);
		}
	}

	private void verifyAssertionSignature(Assertion assertion) {

		if (!assertion.isSigned()) {
			throw new RuntimeException("The SAML Assertion was not signed");
		}

		try {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(assertion.getSignature());

			SignatureValidator.validate(assertion.getSignature(), IDPCredentials.getCredential());

			logger.info("SAML Assertion signature verified");
		} catch (SignatureException e) {
			e.printStackTrace();
		}

	}

	private void setAuthenticatedSession(HttpServletRequest req) {
		req.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
	}

	private void redirectToGotoURL(HttpServletRequest req, HttpServletResponse resp) {
		String gotoURL = (String) req.getSession().getAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE);
		logger.info("Redirecting to requested URL: " + gotoURL);
		try {
			resp.sendRedirect(gotoURL);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void logAuthenticationMethod(Assertion assertion) {
		logger.info("Authentication method: "
				+ assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getURI());
	}

	private void logAuthenticationInstant(Assertion assertion) {
		logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
	}

	private void logAssertionAttributes(Assertion assertion) {
		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
			logger.info("Attribute name: " + attribute.getName());
			for (XMLObject attributeValue : attribute.getAttributeValues()) {
				logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
			}
		}
	}

	private EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
		Response response = (Response) artifactResponse.getMessage();
		return response.getEncryptedAssertions().get(0);
	}

	private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve,
			HttpServletResponse servletResponse) {
		try {

			MessageContext contextout = new MessageContext();

			contextout.setMessage(artifactResolve);

			SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
			signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
			signatureSigningParameters
					.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			SecurityParametersContext securityParametersContext = contextout
					.getSubcontext(SecurityParametersContext.class, true);
			securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);

			InOutOperationContext context = new ProfileRequestContext();
			context.setOutboundMessageContext(contextout);

			AbstractPipelineHttpSOAPClient soapClient = new AbstractPipelineHttpSOAPClient() {
				protected HttpClientMessagePipeline newPipeline() throws SOAPException {
					HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
					HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();

					BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(encoder, decoder);

					pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
					return pipeline;
				}
			};

			HttpClientBuilder clientBuilder = new HttpClientBuilder();

			soapClient.setHttpClient(clientBuilder.buildClient());
			soapClient.send(IDPConstants.ARTIFACT_RESOLUTION_SERVICE, context);

			return (ArtifactResponse) context.getInboundMessageContext().getMessage();
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	private Artifact buildArtifactFromRequest(final HttpServletRequest req) {
		Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
		artifact.setValue(req.getParameter("SAMLart"));
		return artifact;
	}

	private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
		ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(SPConstants.SP_ENTITY_ID);
		artifactResolve.setIssuer(issuer);

		artifactResolve.setIssueInstant(Instant.now());

		artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());

		artifactResolve.setDestination(IDPConstants.ARTIFACT_RESOLUTION_SERVICE);

		artifactResolve.setArtifact(artifact);

		return artifactResolve;
	}

}
