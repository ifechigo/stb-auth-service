package com.suntrustbank.auth.core.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    INTERNAL_SERVER_ERROR(500, "An error occurred, try again!"),
    SERVICE_UNAVAILABLE(503, "Service unavailable"),
    BAD_REQUEST(400, "Bad request"),
    BAD_REQUEST_INVALID_CURRENT_PIN(400, "Invalid pin, please enter your current pin"),
    BAD_REQUEST_INVALID_CURRENT_PASSWORD(400, "Invalid password, please enter your current password"),
    BAD_REQUEST_RESET_FAILED(400, "Reset Failed"),
    BAD_REQUEST_PHONE_VERIFICATION_FAILED(400, "Phone Verification Failed"),
    BAD_REQUEST_EMAIL_VERIFICATION_FAILED(400, "Email Verification Failed"),
    DUPLICATE_REQUEST(409, "email provided already exist"),
    DUPLICATE_PHONE_REQUEST(409, "phone number provided already exist"),
    NOT_FOUND(404, "user doesn't exist"),
    CLIENT_NOT_FOUND(404, "terminal doesn't exist"),
    UN_AUTHENTICATED(401, "Unauthorized"),
    UN_AUTHENTICATED_TOKEN(401, "Unauthorized invalid token"),
    LOGIN_FAILED(401, "Log In failed"),
    UN_AUTHENTICATED_EMAIL_UNVERIFIED(401, "email of this account is yet to be verified");

    private final int code;
    private final String description;
}
