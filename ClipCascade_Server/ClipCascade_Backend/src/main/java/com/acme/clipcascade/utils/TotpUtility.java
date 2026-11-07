package com.acme.clipcascade.utils;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30 second time step, 6 digits) with Base32
 * (RFC 4648) secret encoding. Implemented with the JDK only so no new
 * dependency is required.
 */
public final class TotpUtility {

    public static final int TIME_STEP_SECONDS = 30;
    public static final int CODE_DIGITS = 6;
    public static final int SECRET_BYTES = 20; // 160 bits
    public static final int VERIFY_WINDOW_STEPS = 1; // accept previous/current/next step

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private TotpUtility() {
        // utility class
    }

    public static String generateSecret() {
        byte[] buffer = new byte[SECRET_BYTES];
        SECURE_RANDOM.nextBytes(buffer);
        return base32Encode(buffer);
    }

    public static boolean isValidCodeFormat(String code) {
        return code != null && code.matches("\\d{" + CODE_DIGITS + "}");
    }

    public static boolean verifyCode(String base32Secret, String code) {
        return verifyCode(base32Secret, code, System.currentTimeMillis());
    }

    public static boolean verifyCode(String base32Secret, String code, long timeMillis) {
        if (base32Secret == null || base32Secret.isBlank() || !isValidCodeFormat(code == null ? null : code.trim())) {
            return false;
        }
        String normalized = code.trim();
        long timeCounter = timeMillis / 1000L / TIME_STEP_SECONDS;
        for (long offset = -VERIFY_WINDOW_STEPS; offset <= VERIFY_WINDOW_STEPS; offset++) {
            String expected = generateCode(base32Secret, timeCounter + offset);
            if (MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    normalized.getBytes(StandardCharsets.UTF_8))) {
                return true;
            }
        }
        return false;
    }

    public static String generateCode(String base32Secret, long timeMillis) {
        return generateCode(base32Secret, timeMillis / 1000L / TIME_STEP_SECONDS);
    }

    public static String generateCode(String base32Secret, long timeCounter) {
        byte[] key = base32Decode(base32Secret);
        byte[] data = ByteBuffer.allocate(8).putLong(timeCounter).array();
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int modulus = (int) Math.pow(10, CODE_DIGITS);
            return String.format(Locale.ROOT, "%0" + CODE_DIGITS + "d", binary % modulus);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate TOTP code", e);
        }
    }

    public static String buildOtpAuthUri(String issuer, String accountName, String base32Secret) {
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(accountName);
        return "otpauth://totp/" + encodedIssuer + ":" + encodedAccount
                + "?secret=" + base32Secret
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }

    public static String base32Encode(byte[] data) {
        StringBuilder encoded = new StringBuilder((data.length + 4) / 5 * 8);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(BASE32_ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1F]);
        }
        return encoded.toString();
    }

    public static byte[] base32Decode(String encoded) {
        String cleaned = encoded == null ? "" : encoded.trim().toUpperCase()
                .replace("=", "")
                .replace(" ", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);
            int value = -1;
            for (int a = 0; a < BASE32_ALPHABET.length; a++) {
                if (BASE32_ALPHABET[a] == c) {
                    value = a;
                    break;
                }
            }
            if (value < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
