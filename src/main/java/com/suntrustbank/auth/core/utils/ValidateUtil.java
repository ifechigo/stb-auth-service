package com.suntrustbank.auth.core.utils;

import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidateUtil {
    public static void isValidPinPattern(String pin) throws GenericErrorCodeException {
        if (!pin.matches("\\d{4}")) {
            log.info("==> pin does not match the desired pattern");
            throw GenericErrorCodeException.badRequest("invalid request: Pin must be 4 digits");
        }
    }

    public static void isValidPasswordPattern(String pin) throws GenericErrorCodeException {
        if (!pin.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=!*]).{9,}$")) {
            log.info("==> password does not match the desired pattern");
            throw GenericErrorCodeException.badRequest("Invalid request: Password must be at least 9 characters long, contain an uppercase letter, a lowercase letter, a digit, and a special character.");
        }
    }
}
