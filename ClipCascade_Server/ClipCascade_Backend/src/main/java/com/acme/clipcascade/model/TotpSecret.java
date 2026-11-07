package com.acme.clipcascade.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name = "totp_secrets")
public class TotpSecret {

    @Id
    @NotNull(message = "Username is required")
    private String username;

    @NotNull(message = "Secret is required")
    @Column(nullable = false)
    private String secret;

    @NotNull(message = "Enabled status is required")
    @Column(nullable = false, columnDefinition = "boolean default false")
    private boolean enabled;

    private Long createdAt;

    public TotpSecret() {
        this.enabled = false;
    }

    public TotpSecret(String username, String secret, boolean enabled, Long createdAt) {
        this.username = username;
        this.secret = secret;
        this.enabled = enabled;
        this.createdAt = createdAt;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSecret() {
        return this.secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public boolean getEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Long getCreatedAt() {
        return this.createdAt;
    }

    public void setCreatedAt(Long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "{" +
                " username='" + getUsername() + "'" +
                ", enabled='" + isEnabled() + "'" +
                ", createdAt='" + getCreatedAt() + "'" +
                "}";
    }

}
