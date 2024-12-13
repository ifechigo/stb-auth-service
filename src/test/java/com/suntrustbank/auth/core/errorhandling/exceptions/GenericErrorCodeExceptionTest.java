package com.suntrustbank.auth.core.errorhandling.exceptions;

import com.suntrustbank.auth.core.enums.ErrorCode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GenericErrorCodeExceptionTest {

    @Test
    void createGenericErrorCodeException_withErrorCode() {

        final GenericErrorCodeException genericErrorCodeException = new GenericErrorCodeException(ErrorCode.BAD_REQUEST);

        assertEquals(ErrorCode.BAD_REQUEST, genericErrorCodeException.getErrorCode());
        assertEquals(ErrorCode.BAD_REQUEST.getDescription(), genericErrorCodeException.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, genericErrorCodeException.getHttpStatus());
    }

    @Test
    void createGenericErrorCodeException_withMessage() {

        final GenericErrorCodeException genericErrorCodeException = new GenericErrorCodeException(
                "Bad Request",
                ErrorCode.BAD_REQUEST,
                HttpStatus.BAD_REQUEST
        );

        assertEquals(ErrorCode.BAD_REQUEST, genericErrorCodeException.getErrorCode());
        assertEquals("Bad Request", genericErrorCodeException.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, genericErrorCodeException.getHttpStatus());
    }
}