package com.suntrustbank.auth.providers.services;

import com.suntrustbank.auth.core.configs.keycloak.Credentials;
import com.suntrustbank.auth.core.configs.keycloak.KeycloakConfig;
import com.suntrustbank.auth.core.configs.properties.AuthConfig;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.AESEncryptionUtils;
import com.suntrustbank.auth.core.utils.ValidateUtil;
import com.suntrustbank.auth.providers.dtos.AuthCreationRequest;
import com.suntrustbank.auth.providers.dtos.AuthTokenResponse;
import com.suntrustbank.auth.providers.dtos.UpdatePinRequest;
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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakAdminService {

    @Value("${keycloak.admin_realm}")
    private String adminRealm;

    @Resource(name = "adminUserResource")
    private final UsersResource adminUserResource;

    @Resource
    private final KeycloakConfig config;

    private final AuthConfig authConfig;


    /**
     * invokes keycloak service for user profile creation
     *
     * @param userDTO
     * @return UserRepresentation
     */
    public UserRepresentation createAuthUser(AuthCreationRequest userDTO) throws GenericErrorCodeException {
        String pin = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), userDTO.getPin(), String.class);
        ValidateUtil.isValidPinPattern(pin);

        CredentialRepresentation credential = Credentials.createPinCredentials(pin);
        credential.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(userDTO.getUserId());
        user.setAttributes(new HashMap<>());

        if (StringUtils.hasText(userDTO.getFirstName())) {
            user.setFirstName(userDTO.getFirstName());
        }
        if (StringUtils.hasText(userDTO.getLastName())) {
            user.setLastName(userDTO.getLastName());
        }
        if (!Objects.isNull(userDTO.getPhoneNumber())) {
            user.getAttributes().put(UserAttributes.PHONE_NUMBER.getValue(), Collections.singletonList(userDTO.getPhoneNumber()));
        }
        if (!Objects.isNull(userDTO.getRole())) {
            user.getAttributes().put(UserAttributes.ROLE.getValue(), Collections.singletonList(userDTO.getRole().name()));
        }

        user.setEnabled(true);
        user.setCredentials(Collections.singletonList(credential));
        var userCreationResp = adminUserResource.create(user);
        String body = userCreationResp.readEntity(String.class);
        int status = userCreationResp.getStatus();

        if (HttpStatus.valueOf(status).is2xxSuccessful()) {
            return getUser(userDTO.getUserId());
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
        List<UserRepresentation> resultList = adminUserResource.search(userName);

        if (resultList.isEmpty()) {
            throw GenericErrorCodeException.notFound();
        }
        return resultList.get(0);
    }
    public List<UserRepresentation> getUsers(String userName) {
        return adminUserResource.search(userName);
    }

    /**
     * get user by their phone number
     *
     * @param phoneNumber
     * @return UserRepresentation
     */
    public UserRepresentation getUserByPhoneNumber(String phoneNumber) throws GenericErrorCodeException {
        List<UserRepresentation> resultList = adminUserResource.searchByAttributes(UserAttributes.PHONE_NUMBER.getValue().concat(":" + phoneNumber));

        if (resultList.isEmpty()) {
            throw GenericErrorCodeException.notFound();
        }
        return resultList.get(0);
    }
    public List<UserRepresentation> getUsersByPhoneNumber(String phoneNumber) {
        return adminUserResource.searchByAttributes(UserAttributes.PHONE_NUMBER.getValue().concat(":" + phoneNumber));
    }

    /**
     * get user by their email
     *
     * @param email
     * @return UserRepresentation
     */
    public UserRepresentation getUserByEmail(String email) throws GenericErrorCodeException {
        List<UserRepresentation> resultList = adminUserResource.searchByEmail(email, Boolean.TRUE);

        if (resultList.isEmpty()) {
            throw GenericErrorCodeException.notFound();
        }
        return resultList.get(0);
    }
    public List<UserRepresentation> getUsersByEmail(String email) {
        return adminUserResource.searchByEmail(email, Boolean.TRUE);
    }

    /**
     * finds user using {email} on user profile
     *
     * @param userId
     * @return UserRepresentation
     */
    public UserRepresentation getUserById(String userId) {
        return adminUserResource.get(userId).toRepresentation();
    }

    /**
     * send verification email to user
     *
     * @param email
     * @return UserRepresentation
     */
    public void sendVerificationEmail(String email) throws GenericErrorCodeException {
        var userRes =  adminUserResource.get(getUser(email).getId());

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
        adminUserResource.get(representation.getId()).update(representation);
    }

    /**
     * invokes keycloak to initiate
     * pin update for user's
     *
     * @param userId
     * @param requestDto
     */
    public void updatePin(String userId, UpdatePinRequest requestDto) throws GenericErrorCodeException {
        try {
            loginAuthUser(userId, requestDto.getOldPin());
        } catch (Exception e) {
            throw GenericErrorCodeException.incorrectCurrentPin();
        }

        UserRepresentation user = getUser(userId);

        String pin = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), requestDto.getNewPin(), String.class);
        ValidateUtil.isValidPinPattern(pin);
        CredentialRepresentation credential = Credentials.createPinCredentials(pin);
        credential.setTemporary(false);
        user.setCredentials(Collections.singletonList(credential));

        final UserSessionRepresentation[] sessions = adminUserResource.get(user.getId()).
                getUserSessions().
                toArray(new UserSessionRepresentation[0]);
        for (final UserSessionRepresentation session : sessions) {
            config.adminKeycloak().realm(adminRealm).deleteSession(session.getId());
        }

        updateUser(user);
    }

    /**
     * Generates authentication token for users
     *
     * @param username
     * @param encryptedPin
     * @return AuthTokenResponse
     * @throws GenericErrorCodeException
     */
    public AuthTokenResponse loginAuthUser(String username, String encryptedPin) throws GenericErrorCodeException {
        try {
            String pin = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), encryptedPin, String.class);
            ValidateUtil.isValidPinPattern(pin);
            AccessTokenResponse accessTokenResponse = config.newAdminKeycloakBuilderWithPinCredentials(username, pin)
                .build()
                .tokenManager()
                .grantToken();
            return AuthTokenResponse.map(accessTokenResponse);
        } catch (Exception e) {
            log.error("keycloak user login failed due to error : {}", e.getMessage());
            throw new GenericErrorCodeException("incorrect phone number or pin", ErrorCode.UN_AUTHENTICATED, HttpStatus.UNAUTHORIZED);
        }
    }

    public AuthTokenResponse loginClient(String terminalSerialNo, String terminalSecret) throws GenericErrorCodeException {
        try {
            AccessTokenResponse accessTokenResponse = config.newAdminKeycloakBuilderWithClientCredentials(terminalSerialNo, terminalSecret)
                    .build()
                    .tokenManager()
                    .grantToken();
            return AuthTokenResponse.map(accessTokenResponse);
        } catch (Exception e) {
            log.error("keycloak client login failed due to error : ", e);
            throw new GenericErrorCodeException("invalid credentials parsed", ErrorCode.UN_AUTHENTICATED, HttpStatus.UNAUTHORIZED);
        }
    }
}
