package com.acme.clipcascade.config;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown after a successful password check when the account has TOTP enabled
 * but no TOTP code was supplied with the login request.
 */
public class TotpRequiredException extends AuthenticationException {

    public TotpRequiredException(String message) {
        super(message);
    }
}
