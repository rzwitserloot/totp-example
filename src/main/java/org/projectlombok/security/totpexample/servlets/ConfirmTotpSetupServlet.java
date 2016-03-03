package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
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
 * This servlet confirms that a signing up user verifies that their TOTP device is giving correct codes.
 * 
 * Once this confirmation is complete, a long lived session is created  to track that the device the user is accessing this page from, is now authorized as a logged in
 * device (at least until the session expires).
 * <p>
 * It never renders anything; it always redirects:<ul>
 * <li>If the TOTP verification fails and there's no hope left it goes back to {@link SignupServlet}</li>
 * <li>If the TOTP verification fails and the user should try again, it goes back to {@link SetupTotpServlet}</li>
 * <li>If the TOTP verification succeeds, it sets a cookie to track the login session and goes on to {@link LoggedInUsersServlet}</li>
 * </ul>
 * <p>
 * <em>NB: </em>Some sites, after signing up, force the user to log in as normal. This is user hostile and does not add any meaningful security. You should not do this.
 */
public class ConfirmTotpSetupServlet extends HttpServlet {
	private final UserStore users;
	private final SessionStore sessions;
	private final Totp totp;
	
	public ConfirmTotpSetupServlet(UserStore users, SessionStore sessions, Totp totp) {
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
			result = totp.finishSetupTotp(session, code);
		} catch (TotpException e) {
			error(response, session, e.getMessage(), true);
			return;
		}
		
		String message;
		boolean hopeless;
		switch (result) {
		case SUCCESS:
			String username = session.getOrDefault(Totp.SESSIONKEY_USERNAME, null);
			finishSignup(response, username);
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
			response.sendRedirect("/signup?si=" + session.getSessionKey());
		} else {
			response.sendRedirect("/setup-totp?si=" + session.getSessionKey());
		}
	}
	
	private void finishSignup(HttpServletResponse response, String username) throws IOException {
		ConfirmTotpLoginServlet.addSessionCookie(response, users, username);
		response.sendRedirect("/main");
	}
}
