package org.projectlombok.security.totpexample;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Totp {
	
	private static final long KEY_VALIDATION_WINDOW = TimeUnit.SECONDS.toMillis(30);
	private static final int TIMESKEW = 2;
	private static final Pattern SECRET_PATTERN = Pattern.compile("[a-z2-7]*", Pattern.CASE_INSENSITIVE);
	private static final String BASE32CHARS = "abcdefghijklmnopqrstuvwxyz234567";
	
	public enum VerifyResult {
		FAILED,
		ALREADY_USED,
		VERIFIED
	}
	
	private final String secret;
	
	public static String newSecret(Crypto crypto) {
		return crypto.generate(BASE32CHARS, 16);
	}
	
	public static Totp fromString(String secret) {
		if (secret == null) throw new NullPointerException("secret");
		if (secret.length() != 16) throw new IllegalArgumentException("wrong length secret, expected 16 characters, got " + secret.length());
		if (!SECRET_PATTERN.matcher(secret).matches()) throw new IllegalArgumentException("non-base32 characters in secret");
		return new Totp(secret.toLowerCase());
	}
	
	private Totp(String secret) {
		this.secret = secret;
	}
	
	public String toUri(String username, String application) {
		String app = urlSafe(application);
		String user = urlSafe(username);
		return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%1$s", app, user, secret);
	}
	
	public VerifyResult verify(String verificationCode, String key, boolean trackAttempts) throws GeneralSecurityException {
		byte[] secretBytes = toBytes();
		long normalizedTime = System.currentTimeMillis() / KEY_VALIDATION_WINDOW;
		
		VerifyResult result = VerifyResult.FAILED;
		
		for (long i = normalizedTime - TIMESKEW; i <= normalizedTime + TIMESKEW; i++) {
			int hash = calculateCode(secretBytes, i);
			if (String.format("%06d", hash).equals(verificationCode)) {
				if (trackAttempts && !alreadyUsedScan(key, i, normalizedTime - TIMESKEW)) result = VerifyResult.ALREADY_USED;
				else result = VerifyResult.VERIFIED;
			}
		}
		return result;
	}
	
	private static String urlSafe(String value) {
		try {
			// Google Authenticator doesn't handle '+' correctly
			return URLEncoder.encode(value, "UTF8").replace("+", "%20");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Broken JVM");
		}
	}
	
	private static int calculateCode(byte[] secret, long time) throws GeneralSecurityException {
		Key keySpec = new SecretKeySpec(secret, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(keySpec);
		byte[] hashedTimestamp = mac.doFinal(bigEndian(time));
		int offset = hashedTimestamp[19] & 0xF;
		long truncatedHash = 0L;
		
		for (int i = 0; i < 4; i++) {
			truncatedHash = (truncatedHash << 8) | (hashedTimestamp[offset + i] & 0xff);
		}
		
		truncatedHash = (truncatedHash & 0x7fff_ffff) % 1_000_000;
		return (int) truncatedHash;
	}
	
	private static boolean alreadyUsedScan(String key, long i, long l) {
		return false;
	}
	
	private static byte[] bigEndian(long value) {
		byte[] bytes = new byte[8];
		for (int i = 7; i >= 0; i--) {
			bytes[i] = (byte) (value & 0xffL);
			value >>= 8;
		}
		return bytes;
	}
	
	private byte[] toBytes() {
		byte[] result = new byte[10];
		decode32(result, 0, 0);
		decode32(result, 8, 5);
		return result;
	}
	
	private void decode32(byte[] bytes, int secretOffset, int byteOffset) {
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
