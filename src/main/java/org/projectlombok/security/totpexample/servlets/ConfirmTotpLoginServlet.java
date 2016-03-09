package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionNotFoundException;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.TotpException;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.Totp.CodeVerification;

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
	
	public ConfirmTotpLoginServlet(UserStore users, SessionStore sessions, Totp totp) {
		this.users = users;
		this.sessions = sessions;
		this.totp = totp;
	}
	
	@Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		String code2 = request.getParameter("code2");
		String code3 = request.getParameter("code3");
		String key = request.getParameter("key");
		Session session = sessions.get(key);
		CodeVerification result;
		
		try {
			if (code2 != null && code3 != null) {
				result = totp.finishCheckTotpForCancellingLockout(session, Arrays.asList(code, code2, code3));
			} else {
				result = totp.finishCheckTotp(session, code);
			}
		} catch (TotpException e) {
			error(response, session, e.getMessage(), true);
			return;
		} catch (SessionNotFoundException e) {
			error(response, session, "The session has expired; log in again.", true);
			return;
		}
		
		String message = "";
		boolean toTroubleshooting = false;
		switch (result.getResult()) {
		case SUCCESS:
			String username = session.getOrDefault("username", null);
			finishLogin(response, username);
			return;
		case NOW_LOCKED_OUT:
		case ALREADY_LOCKED_OUT:
			toTroubleshooting = true;
			break;
		case CLOCK_MISMATCH:
			String humanReadableOffset = result.getClockskewAsHumanReadable();
			message = "It looks like your verification device's clock is off. Perhaps it is in the wrong timezone or you can update the Daylight Savings Time setting. Consider turning on 'automatically set time via network'. Set the clock of the device to the correct time and try again. It is off by: " + humanReadableOffset;
			toTroubleshooting = true;
			break;
		case CODE_VERIFICATION_FAILURE:
			message = "Incorrect verification code.";
			break;
		case INVALID_INPUT:
			message = "The input should be 6 digits. Make sure to enter leading zeroes.";
			break;
		case CODE_ALREADY_USED:
			message = "You've already logged in with this code. Wait for your verification device to show another code, then enter it.";
			break;
		default:
			throw new ServletException("Enum not covered: " + result);
		}
		
		error(response, session, message, toTroubleshooting);
	}
	
	private void error(HttpServletResponse response, Session session, String message, boolean toTroubleshooting) throws IOException {
		session.put("errMsg", message);
		if (toTroubleshooting) {
			response.sendRedirect("/troubleshoot-totp?si=" + session.getSessionKey());
		} else {
			response.sendRedirect("/verify-totp?si=" + session.getSessionKey());
		}
	}
	
	private void finishLogin(HttpServletResponse response, String username) throws IOException {
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
