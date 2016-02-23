package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.SessionStoreException;
import org.projectlombok.security.totpexample.UserStore;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class LoggedInUsersServlet extends HttpServlet {
	private final Template mainpageTemplate;
	private final UserStore users;
	
	public LoggedInUsersServlet(Configuration templates, UserStore users) throws IOException {
		this.mainpageTemplate = templates.getTemplate("mainpage.html");
		this.users = users;
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String sessionId = null;
		for (Cookie cookie : request.getCookies()) {
			if ("s".equals(cookie.getName())) {
				sessionId = cookie.getValue();
			}
		}
		
		String username = sessionId == null ? null : users.getUserFromSessionKey(sessionId);
		if (username == null) {
			
			response.sendRedirect("/login?err=" + errorSession.getKey());
		}
		if (sessionKey == null || 
		String sessionKey = request.getParameter("msg");
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
