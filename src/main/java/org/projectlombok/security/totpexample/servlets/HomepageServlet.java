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

/**
 * This servlet serves up a homepage for users that aren't logged in.
 */
public class HomepageServlet extends HttpServlet {
	private final Template homepageTemplate;
	private final SessionStore sessions;
	
	public HomepageServlet(Configuration templates, SessionStore sessions) throws IOException {
		this.homepageTemplate = templates.getTemplate("homepage.html");
		this.sessions = sessions;
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String sessionKey = request.getParameter("si");
		String userMessage = "";
		if (sessionKey != null) {
			try {
				userMessage = sessions.get(sessionKey).getOrDefault("msg", "");
			} catch (SessionStoreException e) {
				userMessage = "";
			}
		}
		Map<String, Object> root = new HashMap<>();
		if (!userMessage.isEmpty()) root.put("userMsg", userMessage);
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			homepageTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: homepage.html", e);
		}
	}
}
