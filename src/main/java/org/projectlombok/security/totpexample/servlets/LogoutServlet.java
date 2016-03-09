package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.UserStore;

/**
 * This servlet wipes all long lived sessions for this user and then redirects (even if no such sessions were found) to the home page.
 */
public class LogoutServlet extends HttpServlet {
	private static final long DEFAULT_TIME_TO_LIVE = TimeUnit.MINUTES.toMillis(30);
	private final UserStore users;
	private final SessionStore sessions;
	
	public LogoutServlet(UserStore users, SessionStore sessions) {
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
		
		users.destroyLongLivedSession(sessionId);
		
		Session msgSession = sessions.create(DEFAULT_TIME_TO_LIVE);
		msgSession.put("msg", "You have been logged out on all devices.");
		response.sendRedirect("/?si=" + msgSession.getSessionKey());
	}
}
