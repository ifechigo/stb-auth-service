package com.suntrustbank.auth.providers.services;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.*;

public interface AdminAccountService {
    BaseResponse createUser(AuthAdminCreationRequest request) throws GenericErrorCodeException;
    BaseResponse loginUser(EncryptedRequest request) throws GenericErrorCodeException;

    BaseResponse updateEmail(String userId, String email) throws GenericErrorCodeException;
    BaseResponse update(String userId, UpdateRequest requestDto) throws GenericErrorCodeException; //update auth profile
    BaseResponse updatePassword(String userId, UpdatePasswordRequest requestDto) throws GenericErrorCodeException; //change pin

    BaseResponse passwordReset(ResetRequest requestDto) throws GenericErrorCodeException; //forgotPin - send OTP
    BaseResponse verifyPasswordResetOtp(ResetOtpRequest requestDto) throws GenericErrorCodeException; //forgotPin - verify otp
    BaseResponse saveNewPassword(PasswordUpdateRequest requestDto) throws GenericErrorCodeException; //forgotPin - save new pin
}
