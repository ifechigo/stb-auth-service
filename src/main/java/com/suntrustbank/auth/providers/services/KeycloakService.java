package com.suntrustbank.auth.providers.services;

import com.suntrustbank.auth.core.configs.keycloak.Credentials;
import com.suntrustbank.auth.core.configs.keycloak.KeycloakConfig;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.AuthCreationRequest;
import com.suntrustbank.auth.providers.dtos.AuthTokenResponse;
import com.suntrustbank.auth.providers.dtos.UpdatePasswordRequest;
import com.suntrustbank.auth.providers.dtos.enums.UserAttributes;
import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.UserSessionRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    @Value("${keycloak.realm}")
    private String realm;

    @Resource
    private final UsersResource userResource;

    @Resource
    private final KeycloakConfig config;


    /**
     * invokes keycloak service for user profile creation
     *
     * @param userDTO
     * @return UserRepresentation
     */
    public UserRepresentation createAuthUser(AuthCreationRequest userDTO) throws GenericErrorCodeException {
        CredentialRepresentation credential = Credentials
                .createPasswordCredentials(userDTO.getPassword());
        credential.setTemporary(false);
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userDTO.getEmail());
        user.setEmail(userDTO.getEmail());
        user.setAttributes(new HashMap<>());

        if (StringUtils.hasText(userDTO.getFirstName())) {
            user.setFirstName(userDTO.getFirstName());
        }
        if (StringUtils.hasText(userDTO.getLastName())) {
            user.setLastName(userDTO.getLastName());
        }
        if (!Objects.isNull(userDTO.getRole())) {
            user.getAttributes().put(UserAttributes.ROLE.getValue(), Collections.singletonList(userDTO.getRole().name()));
        }

        user.setCredentials(Collections.singletonList(credential));
        var userCreationResp = userResource.create(user);
        String body = userCreationResp.readEntity(String.class);
        int status = userCreationResp.getStatus();

        if (HttpStatus.valueOf(status).is2xxSuccessful()) {
            return getUser(userDTO.getEmail());
        } else {
            log.error("keycloak user creation failed with http: {} and error: {} ", status, body);
            if (HttpStatus.valueOf(userCreationResp.getStatus()).is4xxClientError()) {
                throw new GenericErrorCodeException(body, ErrorCode.BAD_REQUEST, HttpStatus.valueOf(status));
            }
            throw new GenericErrorCodeException(body, ErrorCode.INTERNAL_SERVER_ERROR, HttpStatus.valueOf(status));
        }
    }

    /**
     * finds user using {email} on user profile
     *
     * @param userName
     * @return UserRepresentation
     */
    public UserRepresentation getUser(String userName) throws GenericErrorCodeException {
        List<UserRepresentation> resultList = userResource.search(userName);

        if (resultList.isEmpty()) {
            throw GenericErrorCodeException.notFound();
        }
        return resultList.get(0);
    }
    public List<UserRepresentation> getUsers(String userName) {
        return userResource.search(userName);
    }

    /**
     * get user by their phone number
     *
     * @param phoneNumber
     * @return UserRepresentation
     */
    public UserRepresentation getUserByPhoneNumber(String phoneNumber) throws GenericErrorCodeException {
        List<UserRepresentation> resultList = userResource.searchByAttributes(UserAttributes.PHONE_NUMBER.getValue().concat(":" + phoneNumber));

        if (resultList.isEmpty()) {
            throw GenericErrorCodeException.notFound();
        }
        return resultList.get(0);
    }
    public List<UserRepresentation> getUsersByPhoneNumber(String phoneNumber) throws GenericErrorCodeException {
        return userResource.searchByAttributes(UserAttributes.PHONE_NUMBER.getValue().concat(":" + phoneNumber));
    }

    /**
     * finds user using {email} on user profile
     *
     * @param userId
     * @return UserRepresentation
     */
    public UserRepresentation getUserById(String userId) {
        return userResource.get(userId).toRepresentation();
    }

    /**
     * send verification email to user
     *
     * @param email
     * @return UserRepresentation
     */
    public void sendVerificationEmail(String email) throws GenericErrorCodeException {
        var userRes =  userResource.get(getUser(email).getId());

        userRes.sendVerifyEmail();
        userRes.executeActionsEmail(List.of("VERIFY_EMAIL"), 10);
    }

    /**
     * invokes keycloak to update a user's
     * profile information
     *
     * @param representation
     */
    public void updateUser(UserRepresentation representation) {
        userResource.get(representation.getId()).update(representation);
    }

    /**
     * invokes keycloak to initiate
     * password update for user's
     *
     * @param userId
     * @param requestDto
     */
    public void updatePassword(String userId, UpdatePasswordRequest requestDto) throws GenericErrorCodeException {
        try {
            loginAuthUser(userId, requestDto.getOldPassword());
        } catch (Exception e) {
            throw GenericErrorCodeException.incorrectCurrentPassword();
        }

        UserRepresentation user = getUser(userId);

        CredentialRepresentation credential = Credentials.createPasswordCredentials(requestDto.getNewPassword());
        credential.setTemporary(false);
        user.setCredentials(Collections.singletonList(credential));

        final UserSessionRepresentation[] sessions = userResource.get(user.getId()).
                getUserSessions().
                toArray(new UserSessionRepresentation[0]);
        for (final UserSessionRepresentation session : sessions) {
            config.keycloak().realm(realm).deleteSession(session.getId());
        }

        updateUser(user);
    }

    /**
     * Generates authentication token for users
     *
     * @param username
     * @param password
     * @return AuthTokenResponse
     * @throws GenericErrorCodeException
     */
    public AuthTokenResponse loginAuthUser(String username, String password) throws GenericErrorCodeException {
        try {
            AccessTokenResponse accessTokenResponse = config.newKeycloakBuilderWithPasswordCredentials(username, password)
                .build()
                .tokenManager()
                .grantToken();

            return AuthTokenResponse.map(accessTokenResponse);
        } catch (Exception e) {
            log.error("keycloak user login failed due to error : {}", e.getMessage());
            throw new GenericErrorCodeException(e.getLocalizedMessage(), ErrorCode.UN_AUTHENTICATED, HttpStatus.UNAUTHORIZED);
        }
    }
}
