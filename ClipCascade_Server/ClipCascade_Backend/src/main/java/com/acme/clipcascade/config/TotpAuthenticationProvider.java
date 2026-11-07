package com.acme.clipcascade.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.acme.clipcascade.service.TotpService;

/**
 * Password check first (via {@link DaoAuthenticationProvider}), then TOTP when
 * the account has it enabled. Throwing dedicated exceptions lets the failure
 * handler redirect to distinct login-page states without leaking whether the
 * password was correct.
 */
public class TotpAuthenticationProvider extends DaoAuthenticationProvider {

    private final TotpService totpService;

    public TotpAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            TotpService totpService) {

        setUserDetailsService(userDetailsService);
        setPasswordEncoder(passwordEncoder);
        this.totpService = totpService;
    }

    @Override
    protected void additionalAuthenticationChecks(
            UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        super.additionalAuthenticationChecks(userDetails, authentication);

        if (!totpService.isServerEnabled() || !totpService.isEnabled(userDetails.getUsername())) {
            return;
        }

        String code = null;
        if (authentication.getDetails() instanceof TotpWebAuthenticationDetails details) {
            code = details.getTotpCode();
        }

        if (code == null || code.isBlank()) {
            throw new TotpRequiredException("TOTP code required for this account");
        }

        if (!totpService.verifyLoginCode(userDetails.getUsername(), code)) {
            throw new InvalidTotpException("Invalid TOTP code");
        }
    }
}
