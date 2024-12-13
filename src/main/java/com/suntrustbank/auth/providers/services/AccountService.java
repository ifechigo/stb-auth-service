package com.suntrustbank.auth.providers.services;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.*;

public interface AccountService {

    BaseResponse createUser(AuthCreationRequest request) throws GenericErrorCodeException;

    BaseResponse verifyEmail(String reference) throws GenericErrorCodeException;

    void updatePhoneNumber(String userId, String phoneNumber) throws GenericErrorCodeException;

    BaseResponse verifyPhoneNumber(String userId, String otp) throws GenericErrorCodeException;

    BaseResponse loginUser(AuthRequest requestDto) throws GenericErrorCodeException;

    BaseResponse resendVerifyEmailLink(VerifyEmailRequest requestDto) throws GenericErrorCodeException;

    void passwordReset(PasswordResetRequest requestDto); //forgotPassword

    BaseResponse verifyPasswordReset(PasswordUpdateRequest requestDto) throws GenericErrorCodeException;

    BaseResponse update(String userId, UpdateRequest requestDto) throws GenericErrorCodeException;

    BaseResponse updatePassword(String userId, UpdatePasswordRequest requestDto) throws GenericErrorCodeException;
}
