package com.suntrustbank.auth.providers.services.impl;

import com.suntrustbank.auth.core.configs.cache.ICacheService;
import com.suntrustbank.auth.core.configs.cache.InMemoryCacheService;
import com.suntrustbank.auth.core.configs.keycloak.Credentials;
import com.suntrustbank.auth.core.configs.properties.AuthConfig;
import com.suntrustbank.auth.core.configs.properties.OtpDevConfig;
import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.enums.BaseResponseMessage;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.*;
import com.suntrustbank.auth.providers.dtos.*;
import com.suntrustbank.auth.providers.dtos.enums.UserAttributes;
import com.suntrustbank.auth.providers.services.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static com.suntrustbank.auth.core.constants.Common.*;
import static com.suntrustbank.auth.providers.dtos.converter.ModelConverter.jsonToMapConverter;
import static com.suntrustbank.auth.providers.dtos.converter.ModelConverter.mapToJsonConverter;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAccountServiceImpl implements AdminAccountService {

    private final KeycloakAdminService keycloakAdminService;
    private final NotificationService notificationService;
    private final ICacheService accountVerificationCache = new InMemoryCacheService(OTP_EXPIRY_DURATION, TimeUnit.MINUTES);

    private final Environment environment;
    private final OtpDevConfig otpDevConfig;
    private final AuthConfig authConfig;

    @Override
    public BaseResponse createUser(AuthCreationRequest request) throws GenericErrorCodeException {
        if (!keycloakAdminService.getUsers(request.getUserId()).isEmpty() ) {
            throw new GenericErrorCodeException("user already exist", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
        }
        if (!keycloakAdminService.getUsersByPhoneNumber(request.getPhoneNumber()).isEmpty()) {
            throw new GenericErrorCodeException("phone number already exist", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
        }

        keycloakAdminService.createAuthUser(request);

        return BaseResponse.success(keycloakAdminService.loginAuthUser(request.getUserId(), request.getPin()), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse loginUser(EncryptedRequest request) throws GenericErrorCodeException {

        AuthRequest requestDto = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), request.getData(), AuthRequest.class);
        FieldValidatorUtil.validate(requestDto);
        UserRepresentation user;

        try {
            if (StringUtils.hasText(requestDto.getPhoneNumber())) {
                user = keycloakAdminService.getUserByPhoneNumber(requestDto.getPhoneNumber());
                requestDto.setUserId(user.getUsername());
            } else if (StringUtils.hasText(requestDto.getEmail())) {
                user = keycloakAdminService.getUserByEmail(requestDto.getEmail());
                if (!user.isEmailVerified()) {
                    throw GenericErrorCodeException.emailUnverified();
                }
                requestDto.setUserId(user.getUsername());
            }
        } catch (GenericErrorCodeException e) {
            if (e.getErrorCode().equals(ErrorCode.NOT_FOUND)) {
                throw new GenericErrorCodeException("incorrect phone number or pin", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
            }
        }

        return BaseResponse.success(keycloakAdminService.loginAuthUser(requestDto.getUserId(), requestDto.getPin()), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updateEmail(String userId, String email) throws GenericErrorCodeException {
        var userWithEmail = keycloakAdminService.getUsersByEmail(email);

        if (!userWithEmail.isEmpty()) {
            throw GenericErrorCodeException.duplicateEmailRequest();
        }

        UserRepresentation user = keycloakAdminService.getUser(userId);

        user.setEmail(email);
        user.setEmailVerified(true);
        keycloakAdminService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updatePhoneNumber(String userId, String phoneNumber) throws GenericErrorCodeException {
        var userWithPhoneNumber = keycloakAdminService.getUsersByPhoneNumber(phoneNumber);

        if (!userWithPhoneNumber.isEmpty()) {
            throw GenericErrorCodeException.duplicatePhoneNumberRequest();
        }

        var user = keycloakAdminService.getUser(userId);

        if (user.getAttributes() == null) {
            user.setAttributes(new HashMap<>());
        }

        user.getAttributes().put(UserAttributes.PHONE_NUMBER.getValue(), Collections.singletonList(phoneNumber));

        keycloakAdminService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse update(String userId, UpdateRequest requestDto) throws GenericErrorCodeException {
        UserRepresentation user = keycloakAdminService.getUser(userId);

        if (StringUtils.hasText(requestDto.getFirstName())) {
            user.setFirstName(requestDto.getFirstName());
        }
        if (StringUtils.hasText(requestDto.getLastName())) {
            user.setLastName(requestDto.getLastName());
        }

        keycloakAdminService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updatePin(String userId, UpdatePinRequest requestDto) throws GenericErrorCodeException {
        keycloakAdminService.updatePin(userId, requestDto);
        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse pinReset(PinResetRequest requestDto) throws GenericErrorCodeException {
        String userInput = "";
        try {
            try {
                if (StringUtils.hasText(requestDto.getPhoneNumber())) {
                    keycloakAdminService.getUserByPhoneNumber(requestDto.getPhoneNumber());
                    userInput = requestDto.getPhoneNumber();
                } else if (StringUtils.hasText(requestDto.getEmail())) {
                    var user = keycloakAdminService.getUserByEmail(requestDto.getEmail());
                    if (!user.isEmailVerified()) {
                        throw GenericErrorCodeException.emailUnverified();
                    }
                    userInput = requestDto.getEmail();
                } else {
                    throw GenericErrorCodeException.badRequest("invalid user input");
                }
            } catch (GenericErrorCodeException e) {
                if (e.getErrorCode().equals(ErrorCode.NOT_FOUND)) {
                    throw new GenericErrorCodeException("incorrect user", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
                }
                throw e;
            }

            String otp;
            if (environment.acceptsProfiles(PRODUCTION, STAGING)) {
                otp = RandomNumberGenerator.generate(6);
            } else {
                otp = otpDevConfig.getResetPinOtp();
            }

            String reference = RESET_PIN.concat(UUIDGenerator.generate());
            Map<String, Object> valueMap = new HashMap<>();
            valueMap.put(LOGIN_USER, userInput);
            valueMap.put(OTP, otp);
            accountVerificationCache.save(reference, mapToJsonConverter(valueMap));

            notificationService.sendSMS(SmsRequest.builder().build());

            log.info("==> pin reset opt [{}]", otp);
            return BaseResponse.success(PinResetResponse.builder().reference(reference).build(), BaseResponseMessage.SUCCESSFUL);
        } catch (GenericErrorCodeException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error occurred while sending otp to {}:: ", userInput, e);
            throw GenericErrorCodeException.pinResetFailed();
        }
    }

    @Override
    public BaseResponse verifyPinResetOtp(PinResetOtpRequest requestDto) throws GenericErrorCodeException {
        try {
            var value = accountVerificationCache.get(requestDto.getReference());
            if (Objects.isNull(value) || !jsonToMapConverter(value).get(OTP).equals(requestDto.getOtp())) {
                throw new GenericErrorCodeException("invalid otp", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
            }

            jsonToMapConverter(value).remove(OTP);

            String reference = RESET_PIN.concat(UUIDGenerator.generate());
            accountVerificationCache.save(reference, mapToJsonConverter(jsonToMapConverter(value)));

            return BaseResponse.success(PinResetResponse.builder().reference(reference).build(), BaseResponseMessage.SUCCESSFUL);
        } catch (GenericErrorCodeException e) {
            throw e;
        } catch (Exception e) {
            log.error("OTP verification failed for Reference: [{}], Error Message: {}", requestDto.getReference(), e.getMessage());
            throw GenericErrorCodeException.pinResetFailed();
        }
    }

    @Override
    public BaseResponse saveNewPin(PinUpdateRequest requestDto) throws GenericErrorCodeException {
        try {
            var value = accountVerificationCache.get(requestDto.getReference());
            if (Objects.isNull(value)) {
                throw GenericErrorCodeException.pinResetFailed();
            }

            Map<String, Object> mappedValue = jsonToMapConverter(value);
            UserRepresentation user = new UserRepresentation();
            if (mappedValue.get(LOGIN_USER).toString().matches("\\d+")) {
                user = keycloakAdminService.getUserByPhoneNumber(mappedValue.get(LOGIN_USER).toString());
            } else {
                user = keycloakAdminService.getUserByEmail(mappedValue.get(LOGIN_USER).toString());
            }

            String pin = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), requestDto.getPin(), String.class);
            ValidateUtil.isValidPinPattern(pin);

            CredentialRepresentation credential = Credentials.createPinCredentials(pin);
            credential.setTemporary(false);
            user.setCredentials(Collections.singletonList(credential));

            keycloakAdminService.updateUser(user);

            return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
        } catch (Exception e) {
            log.error("Pin update for Reference: [{}] failed, Error Message: {}", requestDto.getReference(), e.getMessage());
            throw GenericErrorCodeException.pinResetFailed();
        }
    }
}
