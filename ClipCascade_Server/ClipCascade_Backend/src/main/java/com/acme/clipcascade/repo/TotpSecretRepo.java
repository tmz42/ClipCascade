package com.acme.clipcascade.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.acme.clipcascade.model.TotpSecret;

public interface TotpSecretRepo extends JpaRepository<TotpSecret, String> {

    TotpSecret findByUsernameIgnoreCase(String username);

}
