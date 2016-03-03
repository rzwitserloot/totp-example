package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.UserStore;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

/**
 * This servlet just serves up a dummy home page for logged in users. Its main feature is that it confirms that the user's login session is valid.
 */
public class LoggedInUsersServlet extends HttpServlet {
	private static final long DEFAULT_TIME_TO_LIVE = TimeUnit.MINUTES.toMillis(30);
	private final Template mainpageTemplate;
	private final UserStore users;
	private final SessionStore sessions;
	
	public LoggedInUsersServlet(Configuration templates, UserStore users, SessionStore sessions) throws IOException {
		this.mainpageTemplate = templates.getTemplate("mainpage.html");
		this.users = users;
		this.sessions = sessions;
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
			sendToLogin(request, response);
			return;
		}
		
		Map<String, Object> root = new HashMap<>();
		root.put("username", username);
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			mainpageTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: mainpage.html", e);
		}
	}
	
	private void sendToLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
		Session errorSession = sessions.create(DEFAULT_TIME_TO_LIVE);
		errorSession.put("errMsg", "Please log in first.");
		response.sendRedirect("/login?si=" + errorSession.getSessionKey());
	}
}
