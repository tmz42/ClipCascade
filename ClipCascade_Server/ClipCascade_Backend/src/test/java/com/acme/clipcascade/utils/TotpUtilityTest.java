package com.acme.clipcascade.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class TotpUtilityTest {

    // RFC 6238 Appendix B test key (ASCII "12345678901234567890") in Base32.
    private static final String RFC6238_SECRET = TotpUtility
            .base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    @Test
    void base32RoundTrip() {
        byte[] data = "Hello, ClipCascade!".getBytes(StandardCharsets.UTF_8);
        assertEquals("Hello, ClipCascade!",
                new String(TotpUtility.base32Decode(TotpUtility.base32Encode(data)), StandardCharsets.UTF_8));
    }

    @Test
    void base32DecodeAcceptsLowercaseAndPadding() {
        assertEquals(RFC6238_SECRET, TotpUtility.base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII)));
        byte[] decoded = TotpUtility.base32Decode(RFC6238_SECRET.toLowerCase() + "==");
        assertEquals("12345678901234567890", new String(decoded, StandardCharsets.US_ASCII));
    }

    @Test
    void base32DecodeRejectsInvalidCharacters() {
        assertThrows(IllegalArgumentException.class, () -> TotpUtility.base32Decode("ABC!DEF"));
    }

    @Test
    void generateSecretIsBase32AndUnique() {
        String secret = TotpUtility.generateSecret();
        assertEquals(32, secret.length()); // 20 bytes -> 32 Base32 chars
        assertTrue(secret.matches("[A-Z2-7]+"));
        assertFalse(secret.equals(TotpUtility.generateSecret()));
    }

    // RFC 6238 Appendix B vectors (SHA-1, 8 digits); our 6-digit code is the
    // last 6 digits of the 8-digit value.
    @Test
    void rfc6238Vectors() {
        assertEquals("287082", TotpUtility.generateCode(RFC6238_SECRET, 59L * 1000L)); // 94287082
        assertEquals("081804", TotpUtility.generateCode(RFC6238_SECRET, 1111111109L * 1000L)); // 07081804
        assertEquals("050471", TotpUtility.generateCode(RFC6238_SECRET, 1111111111L * 1000L)); // 14050471
        assertEquals("005924", TotpUtility.generateCode(RFC6238_SECRET, 1234567890L * 1000L)); // 89005924
        assertEquals("279037", TotpUtility.generateCode(RFC6238_SECRET, 2000000000L * 1000L)); // 69279037
        assertEquals("353130", TotpUtility.generateCode(RFC6238_SECRET, 20000000000L * 1000L)); // 65353130
    }

    @Test
    void verifyCodeAcceptsCurrentAndAdjacentSteps() {
        String code = TotpUtility.generateCode(RFC6238_SECRET, 59L * 1000L);
        assertTrue(TotpUtility.verifyCode(RFC6238_SECRET, code, 59L * 1000L));
        assertTrue(TotpUtility.verifyCode(RFC6238_SECRET, code, (59L + 30L) * 1000L)); // next step
        assertTrue(TotpUtility.verifyCode(RFC6238_SECRET, code, (59L - 30L) * 1000L)); // previous step
        assertFalse(TotpUtility.verifyCode(RFC6238_SECRET, code, (59L + 60L) * 1000L)); // outside window
    }

    @Test
    void verifyCodeRejectsMalformedInput() {
        assertFalse(TotpUtility.verifyCode(RFC6238_SECRET, null));
        assertFalse(TotpUtility.verifyCode(RFC6238_SECRET, ""));
        assertFalse(TotpUtility.verifyCode(RFC6238_SECRET, "12345")); // too short
        assertFalse(TotpUtility.verifyCode(RFC6238_SECRET, "abcdef")); // not digits
        assertFalse(TotpUtility.verifyCode(null, "123456"));
        assertFalse(TotpUtility.verifyCode("!!!", "123456"));
    }

    @Test
    void verifyCodeTrimsWhitespace() {
        String code = TotpUtility.generateCode(RFC6238_SECRET, 59L * 1000L);
        assertTrue(TotpUtility.verifyCode(RFC6238_SECRET, " " + code + " ", 59L * 1000L));
    }

    @Test
    void otpAuthUriContainsSecretAndIssuer() {
        String uri = TotpUtility.buildOtpAuthUri("ClipCascade", "alice@example.com", RFC6238_SECRET);
        assertTrue(uri.startsWith("otpauth://totp/ClipCascade:alice%40example.com?"));
        assertTrue(uri.contains("secret=" + RFC6238_SECRET));
        assertTrue(uri.contains("issuer=ClipCascade"));
        assertTrue(uri.contains("digits=6"));
        assertTrue(uri.contains("period=30"));
    }
}
