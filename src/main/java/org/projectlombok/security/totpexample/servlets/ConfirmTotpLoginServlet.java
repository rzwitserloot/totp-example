package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.TotpException;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.Totp.TotpResult;

/**
 * This servlet confirms that a logging in user enters the right TOTP code and creates a long lived session to track that the device the user is accessing this page from, is now authorized as a logged in
 * device (at least until the session expires).
 * 
 * It never renders anything; it always redirects:<ul>
 * <li>If the TOTP verification fails and there's no hope left it goes back to {@link LoginServlet}</li>
 * <li>If the TOTP verification fails and the user should try again, it goes back to {@link VerifyTotpServlet}</li>
 * <li>If the TOTP verification succeeds, it sets a cookie to track the login session and goes on to {@link LoggedInUsersServlet}</li>
 * </ul>
 */
public class ConfirmTotpLoginServlet extends HttpServlet {
	private final UserStore users;
	private final SessionStore sessions;
	private final Totp totp;
	
	public ConfirmTotpLoginServlet(UserStore users, SessionStore sessions, Totp totp) throws IOException {
		this.users = users;
		this.sessions = sessions;
		this.totp = totp;
	}
	
	@Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		String key = request.getParameter("key");
		Session session = sessions.get(key);
		TotpResult result;
		
		try {
			result = totp.finishCheckTotp(session, code);
		} catch (TotpException e) {
			error(response, session, e.getMessage(), true);
			return;
		}
		
		String message;
		boolean hopeless;
		switch (result) {
		case SUCCESS:
			String username = session.getOrDefault("username", null);
			finishLogin(response, username);
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
			response.sendRedirect("/login?si=" + session.getSessionKey());
		} else {
			response.sendRedirect("/verify-totp?si=" + session.getSessionKey());
		}
	}
	
	private void finishLogin(HttpServletResponse response, String username) throws ServletException, IOException {
		addSessionCookie(response, users, username);
		response.sendRedirect("/main");
	}
	
	static void addSessionCookie(HttpServletResponse response, UserStore users, String username) {
		String sessionCookie = users.createNewLongLivedSession(username);
		Cookie c = new Cookie("s", sessionCookie);
		c.setPath("/");
		// c.setSecure(true);  // TODO security. What happens if we set this without HTTPS?
		response.addCookie(c);
	}
}
