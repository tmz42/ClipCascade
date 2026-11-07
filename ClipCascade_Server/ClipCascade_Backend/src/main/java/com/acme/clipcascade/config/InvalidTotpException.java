package com.acme.clipcascade.config;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown after a successful password check when the supplied TOTP code does
 * not match the account's secret.
 */
public class InvalidTotpException extends AuthenticationException {

    public InvalidTotpException(String message) {
        super(message);
    }
}
