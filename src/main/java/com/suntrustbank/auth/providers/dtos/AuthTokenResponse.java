package com.suntrustbank.auth.providers.dtos;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.AccessTokenResponse;

@Builder
@Getter
@Setter
public class AuthTokenResponse {
    private long expiresIn;

    private String token;

    private String tokenType;

    public static AuthTokenResponse map(AccessTokenResponse accessTokenResponse) {
        return AuthTokenResponse
                .builder()
                .token(accessTokenResponse.getIdToken())
                .expiresIn(accessTokenResponse.getExpiresIn())
                .tokenType(accessTokenResponse.getTokenType())
                .build();
    }
}
