package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.Totp.VerifyResult;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class ConfirmTotpServlet extends HttpServlet {
	private final SessionStore sessions;
	private final Template confirmTotpTemplate;
	
	public ConfirmTotpServlet(Configuration templates, SessionStore sessions) throws IOException {
		this.confirmTotpTemplate = templates.getTemplate("confirmTotp.html");
		this.sessions = sessions;
	}
	
	@Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		String key = request.getParameter("key");
		
		Session session = sessions.get(key);
		String secret = session.getOrDefault("secret", null);
		String username = session.getOrDefault("username", null);
		
		Totp totp = Totp.fromString(secret);
		try {
			VerifyResult verify = totp.verify(code, username, false);
			if (verify != VerifyResult.VERIFIED) {
				error(request, response, session, "codes don't match");
			}
		} catch (GeneralSecurityException e1) {
			throw new ServletException(); 
		}
		
		Map<String, Object> root = new HashMap<>();
//		if (!errorMessage.isEmpty()) root.put("errMsg", errorMessage);
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			confirmTotpTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: setupTotp.html", e);
		}
	}
	
	private void error(HttpServletRequest request, HttpServletResponse response, Session session, String message) throws ServletException, IOException {
		session.put("errMsg", message);
		response.sendRedirect("/setup-totp?err=" + session.getSessionKey());
	}
}
