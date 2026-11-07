package com.acme.clipcascade.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Carries the optional "totp" form parameter from the login request into the
 * authentication object so the TOTP provider can check it after the password.
 */
public class TotpWebAuthenticationDetails extends WebAuthenticationDetails {

    private static final long serialVersionUID = 1L;

    private final String totpCode;

    public TotpWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.totpCode = request.getParameter("totp");
    }

    public String getTotpCode() {
        return this.totpCode;
    }
}
