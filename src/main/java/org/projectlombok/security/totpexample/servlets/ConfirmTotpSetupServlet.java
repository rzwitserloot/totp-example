package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
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
		CodeVerification result;
		
		try {
			result = totp.finishSetupTotp(session, code);
		} catch (TotpException e) {
			error(response, session, e.getMessage(), true);
			return;
		} catch (SessionNotFoundException e) {
			error(response, session, "The session has expired; sign up again.", true);
			return;
		}
		
		String message;
		boolean hopeless;
		switch (result.getResult()) {
		case SUCCESS:
			String username = session.getOrDefault(Totp.SESSIONKEY_USERNAME, null);
			finishSignup(response, username);
			return;
		case CODE_VERIFICATION_FAILURE:
			message = "Incorrect verification code.";
			hopeless = false;
			break;
		case CLOCK_MISMATCH:
			String humanReadableOffset = result.getClockskewAsHumanReadable();
			message = "It looks like your verification device's clock is off. Perhaps it is in the wrong timezone or you can update the Daylight Savings Time setting. Consider turning on 'automatically set time via network'. Set the clock of the device to the correct time and try again. It is off by: " + humanReadableOffset;
			hopeless = false;
			break;
		case INVALID_INPUT:
			message = "The input should be 6 digits. Make sure to enter leading zeroes.";
			hopeless = false;
			break;
		case CODE_ALREADY_USED:
			message = "You've already logged in with this code. Wait for your verification device to show another code, then enter it.";
			hopeless = false;
			break;
		default:
			throw new ServletException("Enum not covered: " + result.getResult());
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
