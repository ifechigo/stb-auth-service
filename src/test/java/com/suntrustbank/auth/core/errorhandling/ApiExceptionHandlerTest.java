package com.suntrustbank.auth.core.errorhandling;


import com.suntrustbank.auth.core.dtos.BaseErrorResponse;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler apiExceptionHandler = new ApiExceptionHandler();

    @Test
    void handleInternalServerError() {
        final ResponseEntity<BaseErrorResponse> response = apiExceptionHandler
                .handleInternalServerError(new Exception());
        assertTrue(response.getStatusCode().is5xxServerError());
        assertNotNull(response.getBody());

        final BaseErrorResponse responseBody = response.getBody();
        assertTrue("ERROR".equalsIgnoreCase(responseBody.getStatus().name()));
        assertTrue(responseBody.getErrors().length > 0);
        assertTrue(responseBody.getMessages().length > 0);
    }

    @Test
    void handleGenericErrorCodeException() {
        final ResponseEntity<BaseErrorResponse> response = apiExceptionHandler
                .handleGenericErrorCodeException(new GenericErrorCodeException(
                        "Unable to find resource",
                        ErrorCode.BAD_REQUEST,
                        HttpStatus.BAD_REQUEST
                ));
        assertTrue(response.getStatusCode().is4xxClientError());
        assertNotNull(response.getBody());

        final BaseErrorResponse responseBody = response.getBody();
        assertTrue("ERROR".equalsIgnoreCase(responseBody.getStatus().name()));
        assertTrue(responseBody.getErrors().length > 0);
        assertTrue(responseBody.getMessages().length > 0);
    }

    @Test
    void handleWebClientResponseException() {
        final ResponseEntity<String> response = apiExceptionHandler
                .handleWebClientResponseException(new WebClientResponseException(
                        HttpStatus.BAD_REQUEST.value(),
                        HttpStatus.BAD_REQUEST.name(),
                        null,
                        new byte[]{},
                        null
                ));
        assertTrue(response.getStatusCode().is4xxClientError());
        assertNotNull(response.getBody());
    }

    @Test
    void handleMethodArgumentNotValidException() throws NoSuchMethodException {
        Method method = this.getClass().getDeclaredMethod("handleMethodArgumentNotValidException");
        final MethodParameter methodParameter = new MethodParameter(method, -1);
        final ResponseEntity<BaseErrorResponse> response = apiExceptionHandler
                .handleMethodArgumentNotValidException(new MethodArgumentNotValidException(
                        methodParameter,
                        new BindException(methodParameter, "methodParameter")
                ));
        assertTrue(response.getStatusCode().is4xxClientError());
        assertNotNull(response.getBody());

        final BaseErrorResponse responseBody = response.getBody();
        assertTrue("ERROR".equalsIgnoreCase(responseBody.getStatus().name()));
        assertTrue(responseBody.getErrors().length > 0);
        assertNotNull(responseBody.getMessages());
    }

    @Test
    void handleMissingServletRequestParameterException() {
        final ResponseEntity<BaseErrorResponse> response = apiExceptionHandler
                .handleMissingServletRequestParameterException(new MissingServletRequestParameterException(
                        "page", "String"
                ));
        assertTrue(response.getStatusCode().is4xxClientError());
        assertNotNull(response.getBody());

        final BaseErrorResponse responseBody = response.getBody();
        assertTrue("ERROR".equalsIgnoreCase(responseBody.getStatus().name()));
        assertTrue(responseBody.getErrors().length > 0);
        assertTrue(responseBody.getMessages().length > 0);
    }

    @Test
    void handleNoResourceFoundException() {
        final ResponseEntity<BaseErrorResponse> response = apiExceptionHandler
                .handleNoResourceFoundException(new NoResourceFoundException(
                        HttpMethod.POST,
                        "request/missing"
                ));
        assertTrue(response.getStatusCode().is4xxClientError());
        assertNotNull(response.getBody());

        final BaseErrorResponse responseBody = response.getBody();
        assertTrue("ERROR".equalsIgnoreCase(responseBody.getStatus().name()));
        assertTrue(responseBody.getErrors().length > 0);
        assertTrue(responseBody.getMessages().length > 0);
    }
}