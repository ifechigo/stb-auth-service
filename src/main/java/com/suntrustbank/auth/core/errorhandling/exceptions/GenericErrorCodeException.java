package com.suntrustbank.auth.core.errorhandling.exceptions;

import com.suntrustbank.auth.core.enums.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@RequiredArgsConstructor
public class GenericErrorCodeException extends Exception {

    private final String message;
    private final ErrorCode errorCode;
    private final HttpStatus httpStatus;

    public GenericErrorCodeException(ErrorCode errorCode) {
        this.errorCode = errorCode;
        this.message = errorCode.getDescription();
        this.httpStatus = HttpStatus.valueOf(errorCode.getCode());
    }

    public static GenericErrorCodeException serverError() {
        return new GenericErrorCodeException(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    public static GenericErrorCodeException serviceUnavailable() {
        return new GenericErrorCodeException(ErrorCode.SERVICE_UNAVAILABLE);
    }

    public static GenericErrorCodeException badRequest(String message) {
        return new GenericErrorCodeException(message, ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
    }

    public static GenericErrorCodeException duplicateEmailRequest() {
        return new GenericErrorCodeException(ErrorCode.DUPLICATE_REQUEST);
    }

    public static GenericErrorCodeException duplicatePhoneNumberRequest() {
        return new GenericErrorCodeException(ErrorCode.DUPLICATE_PHONE_REQUEST);
    }

    public static GenericErrorCodeException notFound() {
        return new GenericErrorCodeException(ErrorCode.NOT_FOUND);
    }

    public static GenericErrorCodeException clientNotFound() {
        return new GenericErrorCodeException(ErrorCode.CLIENT_NOT_FOUND);
    }

    public static GenericErrorCodeException resetFailed() {
        return new GenericErrorCodeException(ErrorCode.BAD_REQUEST_RESET_FAILED);
    }

    public static GenericErrorCodeException phoneVerificationFailed() {
        return new GenericErrorCodeException(ErrorCode.BAD_REQUEST_PHONE_VERIFICATION_FAILED);
    }

    public static GenericErrorCodeException emailVerificationFailed() {
        return new GenericErrorCodeException(ErrorCode.BAD_REQUEST_EMAIL_VERIFICATION_FAILED);
    }

    public static GenericErrorCodeException incorrectCurrentPin() {
        return new GenericErrorCodeException(ErrorCode.BAD_REQUEST_INVALID_CURRENT_PIN);
    }

    public static GenericErrorCodeException incorrectCurrentPassword() {
        return new GenericErrorCodeException(ErrorCode.BAD_REQUEST_INVALID_CURRENT_PASSWORD);
    }

    public static GenericErrorCodeException emailUnverified() {
        return new GenericErrorCodeException(ErrorCode.UN_AUTHENTICATED_EMAIL_UNVERIFIED);
    }

    public static GenericErrorCodeException unAuthorized() {
        return new GenericErrorCodeException(ErrorCode.UN_AUTHENTICATED);
    }

    public static GenericErrorCodeException unAuthorizedToken() {
        return new GenericErrorCodeException(ErrorCode.UN_AUTHENTICATED_TOKEN);
    }
}
