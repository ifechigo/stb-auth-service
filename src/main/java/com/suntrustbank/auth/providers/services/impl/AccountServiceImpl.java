package com.suntrustbank.auth.providers.services.impl;

import com.suntrustbank.auth.core.configs.cache.ICacheService;
import com.suntrustbank.auth.core.configs.cache.InMemoryCacheService;
import com.suntrustbank.auth.core.configs.keycloak.Credentials;
import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.enums.BaseResponseMessage;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.*;
import com.suntrustbank.auth.providers.dtos.enums.UserAttributes;
import com.suntrustbank.auth.providers.services.AccountService;
import com.suntrustbank.auth.providers.services.KeycloakService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    private final ICacheService accountVerificationCache = new InMemoryCacheService(OTP_EXPIRY_DURATION, TimeUnit.MINUTES);


    @Override
    public BaseResponse createUser(AuthCreationRequest request) throws GenericErrorCodeException {
        var userRepresentation = keycloakService.getUsers(request.getEmail());
        if (!userRepresentation.isEmpty()) {
            if (userRepresentation.getFirst().isEmailVerified()) {
                throw GenericErrorCodeException.duplicateEmailRequest();
            }
            return save(request, userRepresentation.getFirst().getId(),
                    AccountVerification.builder().password(request.getPassword()).build());
        }

        var user = keycloakService.createAuthUser(request);
        return save(request, user.getId(), AccountVerification
                .builder()
                .password(request.getPassword())
                .build());
    }

    @Override
    public BaseResponse verifyEmail(String reference) throws GenericErrorCodeException {
        var value = accountVerificationCache.get(reference);
        if (Objects.isNull(value)) {
            throw GenericErrorCodeException.emailVerificationFailed();
        }

        var mappedValue = jsonToMapConverter(value);

        List<String> referenceDataList = List.of(reference.split("_"));

        UserRepresentation user = keycloakService.getUserById(referenceDataList.getLast());
        user.setEnabled(true);
        user.setEmailVerified(true);
        keycloakService.updateUser(user);

        if (referenceDataList.size() == RESEND_EMAIL_REFERENCE_LENGTH && Objects.equals(referenceDataList.getFirst(), RESEND_EMAIL)) {
            return BaseResponse.success("email verified, you can now Log In", BaseResponseMessage.SUCCESSFUL);
        }

//        Map<String, String> messageBody = new HashMap<>();
//        messageBody.put("first_name", user.getEmail().split("@")[0]); //first_name not available here
//        message(WELCOME_TO_BAAS, messageBody, SENDER_EMAIL, user.getEmail(), Message.Templates.WELCOME_TO_BAAS);

        return BaseResponse.success(keycloakService.loginAuthUser(user.getUsername(), (String) mappedValue.get(PASSWORD)), BaseResponseMessage.SUCCESSFUL);
    }

    public void updatePhoneNumber(String userId, String phoneNumber) throws GenericErrorCodeException {
        var userWithPhoneNumber = keycloakService.getUsersByPhoneNumber(phoneNumber);

        if (!userWithPhoneNumber.isEmpty()) {
            throw GenericErrorCodeException.duplicatePhoneNumberRequest();
        }

        var user = keycloakService.getUser(userId);

        if (!user.isEmailVerified()) {
            throw GenericErrorCodeException.emailUnverified();
        }

        UUID uuid = UUID.randomUUID();
        var otp = String.format("%06d", Math.abs(uuid.getLeastSignificantBits()) % 1000000L);

        Map<String, Object> value = new HashMap<>();
        value.put(PHONE_NUMBER, phoneNumber);
        value.put(OTP, otp);

        System.out.println("=== === === Phone Reference === === ===");
        System.out.println(otp);
        System.out.println("=== === === === == == == === === === ===");

        accountVerificationCache.save(PHONE.concat(userId), mapToJsonConverter(value));
    }

    public BaseResponse verifyPhoneNumber(String userId, String otp) throws GenericErrorCodeException {

        var value = accountVerificationCache.get(PHONE.concat(userId));
        if (Objects.isNull(value)) {
            throw GenericErrorCodeException.phoneVerificationFailed();
        }

        Map<String, Object> mappedValue = jsonToMapConverter(value);

        if (!mappedValue.get(OTP).toString().equalsIgnoreCase(otp)) {
            throw GenericErrorCodeException.phoneVerificationFailed();
        }

        var user = keycloakService.getUser(userId);

        if (user.getAttributes() == null) {
            user.setAttributes(new HashMap<>());
        }

        user.getAttributes().put(UserAttributes.PHONE_NUMBER.getValue(), Collections.singletonList(mappedValue.get(PHONE_NUMBER).toString()));

        keycloakService.updateUser(user);

        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse loginUser(AuthRequest requestDto) throws GenericErrorCodeException {

        if (StringUtils.hasText(requestDto.getPhoneNumber())) {
            var user = keycloakService.getUserByPhoneNumber(requestDto.getPhoneNumber());

            requestDto.setEmail(user.getEmail());
        }

        return BaseResponse.success(keycloakService.loginAuthUser(requestDto.getEmail(), requestDto.getPassword()), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse resendVerifyEmailLink(VerifyEmailRequest requestDto) throws GenericErrorCodeException {
        var user = keycloakService.getUser(requestDto.getEmail());

        if (user.isEmailVerified()) {
            return BaseResponse.success("Email verified", BaseResponseMessage.SUCCESSFUL);
        }

        AuthCreationRequest userDTO = AuthCreationRequest.builder()
                .referenceId(requestDto.getReferenceId())
                .email(requestDto.getEmail())
                .build();

        return save(userDTO, user.getId(),
                AccountVerification.builder().password(userDTO.getPassword()).isResendEmailLink(true).build());
    }

    @Override
    public void passwordReset(PasswordResetRequest requestDto) {
        try {
            var user = keycloakService.getUser(requestDto.getEmail());

            if (!user.isEmailVerified()) {
                throw GenericErrorCodeException.emailUnverified();
            }

            String key = UUID.randomUUID().toString();
            Map<String, Object> value = new HashMap<>();
            value.put(EMAIL, requestDto.getEmail());

            accountVerificationCache.save(key, mapToJsonConverter(value));

//            Map<String, String> messageBody = new HashMap<>();
//            messageBody.put("password_reset_link", String.format("%s/auth/reset-password/%s", serviceConfig.getBaseUrl(), key));
//            message(RESET_PASSWORD, messageBody, SENDER_EMAIL, passwordResetRequestDto.getEmail(), Message.Templates.RESET_PASSWORD);

//            keycloakService.sendVerificationEmail(requestDto.getEmail());

            System.out.println("=== === === Password Reference === === ===");
            System.out.println(key);
            System.out.println("=== === === === == == == == === === === ===");
        } catch (Exception e) {
            log.error("Error occurred while sending Password Reset Link to {}:: ", requestDto.getEmail(), e);
        }
    }

    @Override
    public BaseResponse verifyPasswordReset(PasswordUpdateRequest requestDto) throws GenericErrorCodeException {
        try {
            var value = accountVerificationCache.get(requestDto.getReference());
            if (Objects.isNull(value)) {
                throw GenericErrorCodeException.passwordResetFailed();
            }

            Map<String, Object> mappedValue = jsonToMapConverter(value);

            var user = keycloakService.getUser(mappedValue.get(EMAIL).toString());

            CredentialRepresentation credential = Credentials
                    .createPasswordCredentials(requestDto.getPassword());
            credential.setTemporary(false);
            user.setCredentials(Collections.singletonList(credential));

            keycloakService.updateUser(user);

            return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
        } catch (Exception e) {
            log.error("Password update for Reference: [{}] failed, Error Message: {}",
                    requestDto.getReference(), e.getMessage());
            throw GenericErrorCodeException.passwordResetFailed();
        }
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
    public BaseResponse updatePassword(String userId, UpdatePasswordRequest requestDto) throws GenericErrorCodeException {
        keycloakService.updatePassword(userId, requestDto);
        return BaseResponse.success(UPDATED, BaseResponseMessage.SUCCESSFUL);
    }

    /**
     * save user account verification records to cache
     *
     * @param userDTO
     * @param userId
     * @param accountVerification
     * @return
     */
    public BaseResponse save(AuthCreationRequest userDTO, String userId, AccountVerification accountVerification)
        throws GenericErrorCodeException {

        String key;
        if (!accountVerification.isResendEmailLink()) {
            key = String.format("%s_%s", userDTO.getReferenceId(), userId);
        } else {
            key = String.format("%s_%s_%s", RESEND_EMAIL, userDTO.getReferenceId(), userId);
        }

        Map<String, Object> value = new HashMap<>();
        value.put(PASSWORD, accountVerification.getPassword());

        accountVerificationCache.save(key, mapToJsonConverter(value));

//            Map<String, String> messageBody = new HashMap<>();
//            messageBody.put("first_name", userDTO.getFirstName());
//            messageBody.put("verification_link", String.format("%s/auth/verify-email/%s", serviceConfig.getBaseUrl(), key));
//            message(VERIFY_OTP, messageBody, SENDER_EMAIL, userDTO.getEmail(), Message.Templates.VERIFY_USER_SIGNUP_EMAIL);

//        keycloakService.sendVerificationEmail(userDTO.getEmail());

        System.out.println("=== === === Email Reference === === ===");
        System.out.println(key);
        System.out.println("=== === === === == == == === === === ===");


        return BaseResponse.success(AccountVerificationResponse
                .builder()
                .referenceId(userDTO.getReferenceId())
                .expiresIn(Instant.now().plus(OTP_EXPIRY_DURATION, ChronoUnit.MINUTES).getEpochSecond())
                .build(), BaseResponseMessage.SUCCESSFUL);
    }
}
