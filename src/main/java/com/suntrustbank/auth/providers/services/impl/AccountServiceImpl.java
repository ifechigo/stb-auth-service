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
import com.suntrustbank.auth.providers.services.AccountService;
import com.suntrustbank.auth.providers.services.KeycloakService;
import com.suntrustbank.auth.providers.services.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.suntrustbank.auth.core.constants.Common.*;
import static com.suntrustbank.auth.providers.dtos.converter.ModelConverter.jsonToMapConverter;
import static com.suntrustbank.auth.providers.dtos.converter.ModelConverter.mapToJsonConverter;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private final KeycloakService keycloakService;
    private final NotificationService notificationService;
    private final ICacheService accountVerificationCache = new InMemoryCacheService(OTP_EXPIRY_DURATION, TimeUnit.MINUTES);

    private final Environment environment;
    private final OtpDevConfig otpDevConfig;
    private final AuthConfig authConfig;

    @Override
    public BaseResponse createUser(AuthCreationRequest request) throws GenericErrorCodeException {
        if (!keycloakService.getUsers(request.getUserId()).isEmpty() ) {
            throw new GenericErrorCodeException("user already exist", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
        }
        if (!keycloakService.getUsersByPhoneNumber(request.getPhoneNumber()).isEmpty()) {
            throw new GenericErrorCodeException("phone number already exist", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
        }

        keycloakService.createAuthUser(request);

        return BaseResponse.success(keycloakService.loginAuthUser(request.getUserId(), request.getPin()), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse loginUser(EncryptedRequest request) throws GenericErrorCodeException {

        AuthRequest requestDto = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), request.getData(), AuthRequest.class);
        FieldValidatorUtil.validate(requestDto);
        UserRepresentation user;

        try {
            if (StringUtils.hasText(requestDto.getPhoneNumber())) {
                user = keycloakService.getUserByPhoneNumber(requestDto.getPhoneNumber());
                requestDto.setUserId(user.getUsername());
            } else if (StringUtils.hasText(requestDto.getEmail())) {
                user = keycloakService.getUserByEmail(requestDto.getEmail());
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

        return BaseResponse.success(keycloakService.loginAuthUser(requestDto.getUserId(), requestDto.getPin()), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updateEmail(String userId, String email) throws GenericErrorCodeException {
        var userWithEmail = keycloakService.getUsersByEmail(email);

        if (!userWithEmail.isEmpty()) {
            throw GenericErrorCodeException.duplicateEmailRequest();
        }

        UserRepresentation user = keycloakService.getUser(userId);

        user.setEmail(email);
        user.setEmailVerified(true);
        keycloakService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updatePhoneNumber(String userId, String phoneNumber) throws GenericErrorCodeException {
        var userWithPhoneNumber = keycloakService.getUsersByPhoneNumber(phoneNumber);

        if (!userWithPhoneNumber.isEmpty()) {
            throw GenericErrorCodeException.duplicatePhoneNumberRequest();
        }

        var user = keycloakService.getUser(userId);

        if (user.getAttributes() == null) {
            user.setAttributes(new HashMap<>());
        }

        user.getAttributes().put(UserAttributes.PHONE_NUMBER.getValue(), Collections.singletonList(phoneNumber));

        keycloakService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse update(String userId, UpdateRequest requestDto) throws GenericErrorCodeException {
        UserRepresentation user = keycloakService.getUser(userId);

        if (StringUtils.hasText(requestDto.getFirstName())) {
            user.setFirstName(requestDto.getFirstName());
        }
        if (StringUtils.hasText(requestDto.getLastName())) {
            user.setLastName(requestDto.getLastName());
        }

        keycloakService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse updatePin(String userId, UpdatePinRequest requestDto) throws GenericErrorCodeException {
        keycloakService.updatePin(userId, requestDto);
        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse pinReset(PinResetRequest requestDto) throws GenericErrorCodeException {
        String userInput = "";
        try {
            try {
                if (StringUtils.hasText(requestDto.getPhoneNumber())) {
                    keycloakService.getUserByPhoneNumber(requestDto.getPhoneNumber());
                    userInput = requestDto.getPhoneNumber();
                } else if (StringUtils.hasText(requestDto.getEmail())) {
                    var user = keycloakService.getUserByEmail(requestDto.getEmail());
                    if (!user.isEmailVerified()) {
                        throw GenericErrorCodeException.emailUnverified();
                    }
                    userInput = requestDto.getEmail();
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
                user = keycloakService.getUserByPhoneNumber(mappedValue.get(LOGIN_USER).toString());
            } else {
                user = keycloakService.getUserByEmail(mappedValue.get(LOGIN_USER).toString());
            }

            String pin = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), requestDto.getPin(), String.class);
            ValidateUtil.isValidPinPattern(pin);

            CredentialRepresentation credential = Credentials.createPinCredentials(pin);
            credential.setTemporary(false);
            user.setCredentials(Collections.singletonList(credential));

            keycloakService.updateUser(user);

            return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
        } catch (Exception e) {
            log.error("Pin update for Reference: [{}] failed, Error Message: {}", requestDto.getReference(), e.getMessage());
            throw GenericErrorCodeException.pinResetFailed();
        }
    }
}
