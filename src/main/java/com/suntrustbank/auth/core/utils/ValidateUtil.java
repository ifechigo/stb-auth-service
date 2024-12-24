package com.suntrustbank.auth.core.utils;

import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidateUtil {
    public static void isValidPinPattern(String pin) throws GenericErrorCodeException {
        if (!pin.matches("\\d{4}")) {
            log.info("==> pin does not match the desired pattern");
            throw GenericErrorCodeException.badRequest("invalid request");
        }
    }
}
