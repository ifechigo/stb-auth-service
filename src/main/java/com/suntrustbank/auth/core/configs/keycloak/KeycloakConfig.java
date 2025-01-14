package com.suntrustbank.auth.core.configs.keycloak;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {
    //User Config
    @Value("${keycloak.url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client_id}")
    private String clientId;

    @Value("${keycloak.client_secret}")
    private String clientSecret;

    //Admin User Config
    @Value("${keycloak.admin_realm}")
    private String adminRealm;

    @Value("${keycloak.admin_client_id}")
    private String adminClientId;

    @Value("${keycloak.admin_client_secret}")
    private String adminClientSecret;

    @Bean(name = "userKeycloak")
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

    @Bean(name = "adminKeycloak")
    public Keycloak adminKeycloak() {
        return KeycloakBuilder
                .builder()
                .serverUrl(serverUrl)
                .realm(adminRealm)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(adminClientId)
                .clientSecret(adminClientSecret)
                .resteasyClient(ResteasyClientBuilder.newBuilder().build())
                .build();
    }

    @Bean(name = "userResource")
    public UsersResource userResource(@Qualifier("userKeycloak") Keycloak userKeycloak) {
        return userKeycloak.realm(realm).users();
    }

    @Bean(name = "adminUserResource")
    public UsersResource adminUserResource(@Qualifier("adminKeycloak") Keycloak adminKeycloak) {
        return adminKeycloak.realm(adminRealm).users();
    }

    @Bean(name = "clientResource")
    public ClientsResource clientResource(@Qualifier("userKeycloak") Keycloak userKeycloak) {
        return userKeycloak.realm(realm).clients();
    }

    @Bean(name = "adminClientResource")
    public ClientsResource adminClientResource(@Qualifier("adminKeycloak") Keycloak adminKeycloak) {
        return adminKeycloak.realm(adminRealm).clients();
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

    public KeycloakBuilder newAdminKeycloakBuilderWithPasswordCredentials(String username, String password) {
        return KeycloakBuilder.builder()
                .realm(adminRealm)
                .serverUrl(serverUrl)
                .clientId(adminClientId)
                .clientSecret(adminClientSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .scope(OAuth2Constants.SCOPE_OPENID)
                .username(username)
                .password(password);
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
