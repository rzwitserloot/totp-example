package org.projectlombok.security.totpexample;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents TOTP, the protocol, providing API for all TOTP related actions, including setting up, verifying, and unlocking.
 */
public final class Totp {
	public static final String SESSIONKEY_USERNAME = "totpUsername";
	public static final String SESSIONKEY_URI = "totpUri";
	public static final String SESSIONKEY_SECRET = "totpSecret";
	private static final long KEY_VALIDATION_WINDOW = TimeUnit.SECONDS.toMillis(30);
	private static final int ALLOWED_CLOCKSKEW = 3;
	
	// When doing a check where stopping a code guesser isn't relevant, let's scan every possible code up to 25 hours away from now,
	// this should cover every timezone mismatch and a considerable amount of misconfigured clocks.
	private static final int ALLOWED_CLOCKSKEW_LAX = (int) TimeUnit.HOURS.toSeconds(25) * 2;
	
	private static final String BASE32CHARS = "abcdefghijklmnopqrstuvwxyz234567";
	private static final long SETUP_PROCEDURE_TTL = TimeUnit.HOURS.toMillis(1);
	
	/**
	 * Represents a user's relevant TOTP data; this is stored persistently somewhere.
	 */
	public static final class TotpData {
		private final String secret;
		private final boolean lockedOut;
		private final long lastSuccessfulTick;
		
		public TotpData(String secret, boolean lockedOut, long lastSuccessfulTick) {
			this.secret = secret;
			this.lockedOut = lockedOut;
			this.lastSuccessfulTick = lastSuccessfulTick;
		}
		
		public boolean isLockedOut() {
			return lockedOut;
		}
		
		public String getSecret() {
			return secret;
		}
		
		public long getLastSuccessfulTick() {
			return lastSuccessfulTick;
		}
	}
	
	public enum TotpResult {
		SUCCESS,
		ALREADY_LOCKED_OUT,
		NOW_LOCKED_OUT,
		CLOCK_MISMATCH,
		CODE_VERIFICATION_FAILURE,
		CODE_ALREADY_USED,
		INVALID_INPUT;
	}
	
	/**
	 * Represents the result of a code verification, whether successful or failed.
	 */
	public static final class CodeVerification {
		private final TotpResult result;
		
		/** If result is 'SUCCESS', or 'CLOCK_MISMATCH', holds the tick whose verification code was just verified. */
		private final long tick;
		
		/** If result is 'SUCCESS' or 'CLOCK_MISMATCH', the code entered corresponds to the current time plus this number of ticks. */
		private final long clockskew;
		
		CodeVerification(TotpResult result, long tick, long clockskew) {
			this.result = result;
			this.tick = tick;
			this.clockskew = clockskew;
		}
		
		public TotpResult getResult() {
			return result;
		}
		
		public long getTick() {
			return tick;
		}
		
		public long getClockskew() {
			return clockskew;
		}
		
		public String getClockskewAsHumanReadable() {
			if (clockskew == 0L) return "Same time.";
			
			StringBuilder out = new StringBuilder();
			int t = (int) Math.abs(clockskew);
			int hours = t / 120;
			t = t % 120;
			int minutes = t / 2;
			boolean seconds = (t % 2) != 0;
			
			if (hours == 1) {
				out.append("1 hour ");
			} else if (hours > 1) {
				out.append(hours).append(" hours ");
			}
			
			if (minutes == 1) {
				out.append("1 minute ");
			} else if (minutes > 1) {
				out.append(minutes).append(" minutes ");
			}
			
			if (seconds) {
				out.append("30 seconds ");
			}
			
			return out.append(clockskew < 0 ? "behind." : "ahead.").toString();
		}
		
		public boolean isSuccess() {
			return result == TotpResult.SUCCESS;
		}
		
		public boolean isLockedOut() {
			return result == TotpResult.ALREADY_LOCKED_OUT || result == TotpResult.NOW_LOCKED_OUT;
		}
		
		public boolean isCodeVerificationFailure() {
			return result == TotpResult.CLOCK_MISMATCH || result == TotpResult.CODE_VERIFICATION_FAILURE || result == TotpResult.NOW_LOCKED_OUT;
		}
		
		@Override public String toString() {
			switch (result) {
			case CLOCK_MISMATCH: return "Clock mismatch: " + (clockskew * 30) + " seconds.";
			case SUCCESS: return "Success (tick: " + tick + ").";
			case ALREADY_LOCKED_OUT: return "Locked out (already).";
			case NOW_LOCKED_OUT: return "Locked out (now).";
			case CODE_ALREADY_USED: return "Code already used.";
			case CODE_VERIFICATION_FAILURE: return "Incorrect code.";
			case INVALID_INPUT: return "Invalid input.";
			default: return "Unexpected enum type: " + result;
			}
		}
	}
	
	private final UserStore users;
	private final SessionStore sessions;
	private final Crypto crypto;
	
	public Totp(UserStore users, SessionStore sessions, Crypto crypto) {
		this.users = users;
		this.sessions = sessions;
		this.crypto = crypto;
	}
	
	/**
	 * Generates a new TOTP key pair for the given user.
	 */
	public Session startSetupTotp(String username, String applicationName) {
		String secret = crypto.generate(BASE32CHARS, 16);
		Session session = sessions.create(SETUP_PROCEDURE_TTL);
		String uri = toUri(username, applicationName, secret);
		session.put(SESSIONKEY_SECRET, secret);
		session.put(SESSIONKEY_URI, uri);
		session.put(SESSIONKEY_USERNAME, username);
		return session;
	}
	
	public CodeVerification finishSetupTotp(Session session, String verificationCode) {
		if (session == null) throw new SessionNotFoundException("Session expired / nonexistent");
		String secret = session.getOrDefault(SESSIONKEY_SECRET, null);
		String username = session.getOrDefault(SESSIONKEY_USERNAME, null);
		if (secret == null || username == null) throw new TotpException("TOTP setup process not started");
		CodeVerification result = verifyCodeLax(secret, Collections.singletonList(verificationCode), 0L);
		if (result.result == TotpResult.SUCCESS) {
			// TODO review all these session.getOrDefaults; I'd really just rather do a getAndItNeedsToBeThere kind of call here. It should be, but bad stuff happens if this password isn't in here.
			String password = session.getOrDefault("password", null);
			users.createUserWithTotp(username, password.toCharArray(), secret, result.tick - 1);
		}
		return result;
	}
	
	/**
	 * TODO SECURITY: Do *NOT* give any feedback on the TotpStatus of any user unless they have already entered the correct password.
	 */
	public TotpData startCheckTotp(String username) {
		return users.getTotpData(username);
	}
	
	/**
	 * @param sessionKey A session started with {@link #startCheckTotp(String)}.
	 */
	public CodeVerification finishCheckTotp(Session session, String verificationCode) {
		if (session == null) throw new SessionNotFoundException("Session expired / nonexistent");
		String username = session.getOrDefault("username", null);
		TotpData userData = users.getTotpData(username);
		if (userData.isLockedOut()) return new CodeVerification(TotpResult.ALREADY_LOCKED_OUT, 0L, 0L);
		CodeVerification result = verifyCode(userData.getSecret(), verificationCode, userData.getLastSuccessfulTick());
		if (result.result == TotpResult.SUCCESS) {
			users.updateLastSuccessfulTick(username, result.tick);
			return result;
		}
		
		if (result.isCodeVerificationFailure()) {
			users.markLockedOut(username);
			return new CodeVerification(TotpResult.NOW_LOCKED_OUT, 0L, 0L);
		}
		
		return result;
	}
	
	/**
	 * This call requires at least 3 consecutive codes ({@code verificationCodes.size()} must be 3 or more).
	 * 
	 * This call will try TOTP verification even if this user has reached the lockout limit, and the lockout limit is not incremented with this call.
	 */
	public CodeVerification finishCheckTotpForCancellingLockout(Session session, Collection<String> verificationCodes) {
		if (verificationCodes.size() < 3) throw new IllegalArgumentException("At least 3 codes required. 3 to 4 are suggested.");
		if (session == null) throw new TotpException("Session expired / nonexistent");
		
		String username = session.getOrDefault("username", null);
		TotpData userData = users.getTotpData(username);
		CodeVerification result = verifyCodeLax(userData.getSecret(), verificationCodes, userData.getLastSuccessfulTick());
		if (result.result == TotpResult.SUCCESS) {
			users.clearLockedOut(username);
			users.updateLastSuccessfulTick(username, result.tick);
		}
		
		return result;
	}
	
	private static String toUri(String username, String application, String secret) {
		String app = urlSafe(application);
		String user = urlSafe(username);
		return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%1$s", app, user, secret);
	}
	
	/**
	 * maps 0, 1, 2, 3, 4, 5, 6, 7, ... to 0, -1, 1, -2, 2, -3, 3, ...
	 */
	private static long clockskewIndexToDelta(int idx) {
		return (idx + 1) / 2 * (1 - (idx % 2) * 2);
	}
	
	private CodeVerification verifyCode(String secret, String verificationCode, long lastSuccessfulTick) {
		if (!validCodeInput(verificationCode)) {
			return new CodeVerification(TotpResult.INVALID_INPUT, 0L, 0L);
		}
		
		byte[] secretBytes = toBytes(secret);
		long tick = System.currentTimeMillis() / KEY_VALIDATION_WINDOW;
		
		for (int i = 0; i <= (ALLOWED_CLOCKSKEW * 2); i++) {
			long delta = clockskewIndexToDelta(i);
			long t = tick + delta;
			if (calculateCode(secretBytes, t).equals(verificationCode)) {
				if (t <= lastSuccessfulTick) {
					return new CodeVerification(TotpResult.CODE_ALREADY_USED, t, delta);
				}
				return new CodeVerification(TotpResult.SUCCESS, t, delta);
			}
		}
		
		return new CodeVerification(TotpResult.CODE_VERIFICATION_FAILURE, 0L, 0L);
	}
	
	private boolean validCodeInput(String in) {
		if (in.length() != 6) return false;
		
		for (int i = 0; i < in.length(); i++) {
			char c = in.charAt(i);
			if (c < '0' || c > '9') return false;
		}
		
		return true;
	}
	
	private CodeVerification verifyCodeLax(String secret, Collection<String> verificationCodes, long lastSuccessfulTick) {
		byte[] secretBytes = toBytes(secret);
		long tick = System.currentTimeMillis() / KEY_VALIDATION_WINDOW;
		
		for (String code : verificationCodes) {
			if (!validCodeInput(code)) {
				return new CodeVerification(TotpResult.INVALID_INPUT, 0L, 0L);
			}
		}
		
		Iterator<String> it = verificationCodes.iterator();
		String firstCode = it.next();
		
		for (int i = 0; i <= (ALLOWED_CLOCKSKEW_LAX * 2); i++) {
			long delta = clockskewIndexToDelta(i);
			long t = tick + delta;
			boolean passable = i < ALLOWED_CLOCKSKEW;
			
			if (calculateCode(secretBytes, t).equals(firstCode)) {
				if (verifyFollowupCodes(secretBytes, t + 1, it)) {
					TotpResult result;
					if (!passable) {
						result = TotpResult.CLOCK_MISMATCH;
					} else if (t <= lastSuccessfulTick) {
						result = TotpResult.CODE_ALREADY_USED;
					} else {
						result = TotpResult.SUCCESS;
					}
					return new CodeVerification(result, t, delta);
				}
			}
		}
		
		return new CodeVerification(TotpResult.CODE_VERIFICATION_FAILURE, 0L, 0L);
	}
	
	private boolean verifyFollowupCodes(byte[] secretBytes, long startTick, Iterator<String> input) {
		while (input.hasNext()) {
			if (!calculateCode(secretBytes, startTick++).equals(input.next())) {
				return false;
			}
		}
		
		return true;
	}
	
	private static String urlSafe(String value) {
		try {
			// Google Authenticator doesn't handle '+' correctly
			return URLEncoder.encode(value, "UTF8").replace("+", "%20");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Broken JVM");
		}
	}
	
	private static String calculateCode(byte[] secret, long time) {
		Key keySpec = new SecretKeySpec(secret, "HmacSHA1");
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA1");
			mac.init(keySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO review what kind of exception this should be.
			throw new InternalError("HmacSHA1 algorithm is not available; check your JVM security settings, they may have been restricted");
		} catch (InvalidKeyException e) {
			throw new TotpException("Invalid secret");
		}
		byte[] hashedTimestamp = mac.doFinal(bigEndian(time));
		int offset = hashedTimestamp[19] & 0xF;
		long truncatedHash = 0L;
		
		for (int i = 0; i < 4; i++) {
			truncatedHash = (truncatedHash << 8) | (hashedTimestamp[offset + i] & 0xff);
		}
		
		truncatedHash = (truncatedHash & 0x7fff_ffff) % 1_000_000;
		return String.format("%06d", truncatedHash);
	}
	
	private static byte[] bigEndian(long value) {
		byte[] bytes = new byte[8];
		for (int i = 7; i >= 0; i--) {
			bytes[i] = (byte) (value & 0xffL);
			value >>= 8;
		}
		return bytes;
	}
	
	private static byte[] toBytes(String secret) {
		byte[] result = new byte[10];
		decode32(secret, result, 0, 0);
		decode32(secret, result, 8, 5);
		return result;
	}
	
	private static void decode32(String secret, byte[] bytes, int secretOffset, int byteOffset) {
		int[] values = new int[8];
		for (int i = 0; i < 8; i++) {
			values[i] = BASE32CHARS.indexOf(secret.charAt(i + secretOffset));
		}
		bytes[0 + byteOffset] = (byte) ((((values[0] & 0x1f) << 3) | ((values[1] & 0x1c) >> 2)) & 0xff);
		bytes[1 + byteOffset] = (byte) ((((values[1] & 0x03) << 6) | ((values[2] & 0x1f) << 1) | ((values[3] & 0x10) >> 4)) & 0xff);
		bytes[2 + byteOffset] = (byte) ((((values[3] & 0x0f) << 4) | ((values[4] & 0x1e) >> 1)) & 0xff);
		bytes[3 + byteOffset] = (byte) ((((values[4] & 0x01) << 7) | ((values[5] & 0x1f) << 2) | ((values[6] & 0x18) >> 3)) & 0xff);
		bytes[4 + byteOffset] = (byte) ((((values[6] & 0x07) << 5) | (values[7] & 0x1f)) & 0xff);
	}
}
