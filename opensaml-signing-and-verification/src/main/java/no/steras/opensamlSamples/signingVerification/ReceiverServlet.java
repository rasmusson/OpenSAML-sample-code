package no.steras.opensamlSamples.signingVerification;

import java.io.File;
import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

public class ReceiverServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(ReceiverServlet.class);
	private static final String SENDER_METADATA_PATH = "sender-metadata.xml";
	private static final String SENDER_ENTITY_ID = "sender.example.com";

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.setHttpServletRequest(req);

		AuthnRequest authnRequest;
		try {
			decoder.initialize();

			decoder.decode();
			MessageContext messageContext = decoder.getMessageContext();
			authnRequest = (AuthnRequest) messageContext.getMessage();
			logger.info("verifySignatureUsingSignatureValidator");
			verifySignatureUsingSignatureValidator(authnRequest);
			logger.info("verifySignatureUsingMessageHandler");
			verifySignatureUsingMessageHandler(messageContext);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		logger.info("AuthnRequest message: ");
		OpenSAMLUtils.logSAMLObject(authnRequest);

		Writer w = resp.getWriter();
		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>"
				+ "<body><h1>Message recieved and signature verified. Results in the console log</h1>" + "</body>"
				+ "</html>");
	}

	private MetadataCredentialResolver getMetadataCredentialResolver() throws Exception {
		final MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();

		File metadataFile = new File(getClass().getClassLoader().getResource(SENDER_METADATA_PATH).toURI());

		final FilesystemMetadataResolver metadataResolver = new FilesystemMetadataResolver(metadataFile);
		metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
		metadataResolver.setParserPool(OpenSAMLUtils.getParserPool());
		metadataResolver.initialize();

		final PredicateRoleDescriptorResolver roleResolver = new PredicateRoleDescriptorResolver(metadataResolver);

		final KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap
				.buildBasicInlineKeyInfoCredentialResolver();

		metadataCredentialResolver.setKeyInfoCredentialResolver(keyResolver);
		metadataCredentialResolver.setRoleDescriptorResolver(roleResolver);

		metadataCredentialResolver.initialize();
		roleResolver.initialize();

		return metadataCredentialResolver;
	}

	private void verifySignatureUsingSignatureValidator(AuthnRequest authnRequest) throws Exception {
		// Get resolver to extract public key from metadata
		MetadataCredentialResolver metadataCredentialResolver = getMetadataCredentialResolver();

		// Set criterion to get relevant certificate
		CriteriaSet criteriaSet = new CriteriaSet();

		criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
		criteriaSet.add(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
		criteriaSet.add(new ProtocolCriterion(SAMLConstants.SAML20P_NS));
		criteriaSet.add(new EntityIdCriterion(SENDER_ENTITY_ID));

		// Resolve credential
		Credential credential = metadataCredentialResolver.resolveSingle(criteriaSet);

		// Verify signature format
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(authnRequest.getSignature());

		// Verify signature
		SignatureValidator.validate(authnRequest.getSignature(), credential);
		logger.info("Signature verified using SignatureValidator");
	}

	private ExplicitKeySignatureTrustEngine buildTrustEngine() throws Exception {
		final KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap
				.buildBasicInlineKeyInfoCredentialResolver();
		ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(
				getMetadataCredentialResolver(), keyInfoResolver);

		return trustEngine;

	}

	private SignatureValidationParameters buildSignatureValidationParameters() throws Exception {
		SignatureValidationParameters validationParameters = new SignatureValidationParameters();
		validationParameters.setSignatureTrustEngine(buildTrustEngine());
		return validationParameters;
	}

	private void verifySignatureUsingMessageHandler(MessageContext context) throws Exception {
		SecurityParametersContext secParamsContext = context.getSubcontext(SecurityParametersContext.class, true);
		secParamsContext.setSignatureValidationParameters(buildSignatureValidationParameters());

		SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
		peerEntityContext.setEntityId(SENDER_ENTITY_ID);
		peerEntityContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

		SAMLProtocolContext protocolContext = context.getSubcontext(SAMLProtocolContext.class, true);
		protocolContext.setProtocol(SAMLConstants.SAML20P_NS);

		SAMLProtocolMessageXMLSignatureSecurityHandler signatureValidationHanlder = new SAMLProtocolMessageXMLSignatureSecurityHandler();
		signatureValidationHanlder.invoke(context);

		if (!peerEntityContext.isAuthenticated()) {
			throw new SecurityException("Message not signed");
		}
	}
}
