package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.SessionStoreException;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class SignupServlet extends HttpServlet {
	private final Template signupTemplate;
	private final SessionStore sessions;
	
	public SignupServlet(Configuration templates, SessionStore sessions) throws IOException {
		this.signupTemplate = templates.getTemplate("signup.html");
		this.sessions = sessions;
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String sessionKey = request.getParameter("err");
		String errorMessage = "";
		if (sessionKey != null) {
			try {
				errorMessage = sessions.get(sessionKey).getOrDefault("errMsg", "");
			} catch (SessionStoreException e) {
				// TODO: Abstract away a log concept with the notion of 'auth' logs with a bunch of SECURITY notes about how to do that properly.
				System.err.println(e);
				e.printStackTrace();
			}
		}
		Map<String, Object> root = new HashMap<>();
		if (!errorMessage.isEmpty()) root.put("errMsg", errorMessage);
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			signupTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: signup.html", e);
		}
	}
}
