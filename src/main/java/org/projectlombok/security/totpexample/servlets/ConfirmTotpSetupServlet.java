package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.TotpException;
import org.projectlombok.security.totpexample.Totp.TotpResult;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class ConfirmTotpSetupServlet extends HttpServlet {
	private final SessionStore sessions;
	private final Template confirmTotpSetupTemplate;
	private final Totp totp;
	
	public ConfirmTotpSetupServlet(Configuration templates, SessionStore sessions, Totp totp) throws IOException {
		this.confirmTotpSetupTemplate = templates.getTemplate("confirmTotpSetup.html");
		this.sessions = sessions;
		this.totp = totp;
	}
	
	@Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		String key = request.getParameter("key");
		Session session = sessions.get(key);
		TotpResult result;
		
		try {
			result = totp.finishSetupTotp(session, code);
		} catch (TotpException e) {
			error(response, session, e.getMessage(), true);
			return;
		}
		
		String message;
		boolean hopeless;
		switch (result) {
		case SUCCESS:
			renderPage(response);
			return;
		case ALREADY_LOCKED_OUT:
			message = "Due to repeated wrong verification code entry, this account was already locked out.";
			hopeless = true;
			break;
		case NOW_LOCKED_OUT:
			message = "Due to repeated wrong verification code entry, this account has been locked out.";
			hopeless = true;
			break;
		case CODE_VERIFICATION_FAILURE:
			message = "Incorrect verification code.";
			hopeless = false;
			break;
		case CLOCK_MISMATCH_DST:
			message = "It looks like your verification device is off by an hour. Perhaps it is in the wrong timezone or you can update the Daylight Savings Time setting.";
			hopeless = false;
			break;
		case CLOCK_MISMATCH_NEARBY:
			message = "It looks like your verification device is off by a few minutes. Set the clock of the device to the correct time, and consider turning on 'automatically set time via network' if available.";
			hopeless = false;
			break;
		case INVALID_INPUT:
			message = "The input should be 6 digits. Make sure to enter leading zeroes.";
			hopeless = false;
			break;
		case SESSION_EXPIRED:
			message = "The session has expired; log in again.";
			hopeless = true;
			break;
		case CODE_ALREADY_USED:
			message = "You've already logged in with this code. Wait for your verification device to show another code, then enter it.";
			hopeless = false;
			break;
		default:
			throw new ServletException("Enum not covered: " + result);
		}
		
		error(response, session, message, hopeless);
	}
	
	private void error(HttpServletResponse response, Session session, String message, boolean hopeless) throws IOException {
		session.put("errMsg", message);
		if (hopeless) {
			response.sendRedirect("/signup?err=" + session.getSessionKey());
		} else {
			response.sendRedirect("/setup-totp?err=" + session.getSessionKey());
		}
	}
	
	private void renderPage(HttpServletResponse response) throws ServletException, IOException {
		Map<String, Object> root = new HashMap<>();
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			confirmTotpSetupTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: confirmTotpSetup.html", e);
		}
	}
}
