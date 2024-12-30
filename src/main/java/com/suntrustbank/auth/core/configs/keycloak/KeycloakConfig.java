package com.suntrustbank.auth.core.configs.keycloak;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {
    @Value("${keycloak.url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client_id}")
    private String clientId;

    @Value("${keycloak.client_secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloak() {
        return KeycloakBuilder
                .builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .resteasyClient(ResteasyClientBuilder.newBuilder().build())
                .build();
    }

    @Bean
    public UsersResource registerUserResource() {
        return keycloak().realm(realm).users();
    }

    @Bean
    public ClientsResource registerClientResource() {
        return keycloak().realm(realm).clients();
    }

    public KeycloakBuilder newKeycloakBuilderWithPinCredentials(String username, String pin) {
        return KeycloakBuilder.builder()
                .realm(realm)
                .serverUrl(serverUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .scope(OAuth2Constants.SCOPE_OPENID)
                .username(username)
                .password(pin);
    }

    public KeycloakBuilder newKeycloakBuilderWithClientCredentials(String terminalSerialNo, String terminalSecret) {
        return KeycloakBuilder.builder()
                .realm(realm)
                .serverUrl(serverUrl)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .scope(OAuth2Constants.SCOPE_OPENID)
                .clientId(terminalSerialNo)
                .clientSecret(terminalSecret);
    }
}
