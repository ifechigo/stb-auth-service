package com.suntrustbank.auth.core.configs.keycloak;

import org.keycloak.representations.idm.CredentialRepresentation;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Credentials {

    public static CredentialRepresentation createPasswordCredentials(String password) {
        CredentialRepresentation passwordCredentials = new CredentialRepresentation();
        passwordCredentials.setTemporary(false);
        passwordCredentials.setType(CredentialRepresentation.PASSWORD);
        passwordCredentials.setValue(password);
        return passwordCredentials;
    }
}
