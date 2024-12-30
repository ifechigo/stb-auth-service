package com.suntrustbank.auth.providers.services;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.*;

public interface AccountService {
    BaseResponse createUser(AuthCreationRequest request) throws GenericErrorCodeException;
    BaseResponse loginUser(EncryptedRequest request) throws GenericErrorCodeException;

    BaseResponse updatePhoneNumber(String userId, String phoneNumber) throws GenericErrorCodeException;
    BaseResponse updateEmail(String userId, String email) throws GenericErrorCodeException;
    BaseResponse update(String userId, UpdateRequest requestDto) throws GenericErrorCodeException; //update auth profile
    BaseResponse updatePin(String userId, UpdatePinRequest requestDto) throws GenericErrorCodeException; //change pin

    BaseResponse pinReset(PinResetRequest requestDto) throws GenericErrorCodeException; //forgotPin - send OTP
    BaseResponse verifyPinResetOtp(PinResetOtpRequest requestDto) throws GenericErrorCodeException; //forgotPin - verify otp
    BaseResponse saveNewPin(PinUpdateRequest requestDto) throws GenericErrorCodeException; //forgotPin - save new pin
}
