package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;

import freemarker.template.Configuration;
import freemarker.template.Template;

public class SetupTotpServlet extends HttpServlet {
	// SECURITY NOTE: TODO - explain this in some more detail.
	private static final long DEFAULT_EXPIRY = TimeUnit.MINUTES.toMillis(30);
	private final SessionStore sessions;
	private final Template setupTotpTemplate;
	
	public SetupTotpServlet(Configuration templates, SessionStore sessions) throws IOException {
//		this.setupTotpTemplate = templates.getTemplate("setupTotp.html");
		this.setupTotpTemplate = null; // TOTP
		this.sessions = sessions;
	}
	
	@Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String password2 = request.getParameter("password2");
		
		if (username == null || username.isEmpty()) {
			error(request, response, "You need to pick a username.");
			return;
		}
		
		if (password == null || password.isEmpty()) {
			error(request, response, "Please choose a password.");
			return;
		}
		
		if (password2 == null || password2.isEmpty()) {
			error(request, response, "Please repeat your preferred password in the 'confirm password' box.");
			return;
		}
		
		if (!password.equals(password2)) {
			error(request, response, "The passwords in both password boxes did not match.");
			return;
		}
		
		if (password.length() < 8) {
			/* SECURITY NOTE:
			 * Do not add any further restrictions to a password:
			 * 
			 * - Do not require a mix of uppercase and lowercase characters.
			 * - Do not require a digit or a special character.
			 * - Do not disallow passwords with spaces. Do not disallow any characters, in fact.
			 * - Do not disallow passwords that are _longer_ than some limit. Really long passwords are fine.
			 * 
			 * Such restrictions are proven not to actually do much. For example, if you require a digit, it'll
			 * usually be a '1' and it'll be at the end. This doesn't meaningfully increase entropy at all.
			 * 
			 * The existence of TOTP will help a lot in reducing the issues with users picking easily guessed passwords.
			 */
			error(request, response, "Passwords need to be at least 8 characters long.");
			return;
		}
	}
	
	private void error(HttpServletRequest request, HttpServletResponse response, String message) throws ServletException, IOException {
		Session session = sessions.create(System.currentTimeMillis() + DEFAULT_EXPIRY);
		session.put("errMsg", message);
		response.sendRedirect("/signup?err=" + session.getSessionKey());
	}
}
