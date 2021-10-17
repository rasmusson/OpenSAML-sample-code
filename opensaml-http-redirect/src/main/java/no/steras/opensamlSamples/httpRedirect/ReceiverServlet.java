package no.steras.opensamlSamples.httpRedirect;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class ReceiverServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(ReceiverServlet.class);

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
		decoder.setHttpServletRequest(req);

		AuthnRequest authnRequest;
		try {
			decoder.initialize();

			decoder.decode();
			MessageContext messageContext = decoder.getMessageContext();
			authnRequest = (AuthnRequest) messageContext.getMessage();

		} catch (ComponentInitializationException | MessageDecodingException e) {
			throw new RuntimeException(e);
		}

		logger.info("AuthnRequest recieved");
		logger.info("AuthnRequest redirect URL: ");
		logger.info(req.getRequestURL().toString() + "?" + req.getQueryString());
		logger.info("AuthnRequest message: ");
		OpenSAMLUtils.logSAMLObject(authnRequest);

		Writer w = resp.getWriter();
		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>" + "<body><h1>AuthnRequest received. Results in the console log</h1>"
				+ "</body>" + "</html>");
	}

}
