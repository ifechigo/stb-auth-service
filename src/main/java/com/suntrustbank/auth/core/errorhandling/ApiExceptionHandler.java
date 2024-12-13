package com.suntrustbank.auth.core.errorhandling;


import com.suntrustbank.auth.core.dtos.BaseErrorResponse;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Arrays;
import java.util.List;

@Slf4j
@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ApiExceptionHandler {

    private static final String EXCEPTION_WAS_THROWN = "Exception was thrown:: ";

    @ExceptionHandler(Exception.class)
    public ResponseEntity<BaseErrorResponse> handleInternalServerError(Exception e) {
        log.error(EXCEPTION_WAS_THROWN, e);
        return ResponseEntity.internalServerError()
                .body(mapErrors(ErrorCode.INTERNAL_SERVER_ERROR));
    }

    @ExceptionHandler(GenericErrorCodeException.class)
    public ResponseEntity<BaseErrorResponse> handleGenericErrorCodeException(GenericErrorCodeException e) {
        log.error(EXCEPTION_WAS_THROWN, e);

        if (StringUtils.hasText(e.getMessage())) {
            return ResponseEntity.status(e.getHttpStatus())
                    .body(mapErrorCode(e.getErrorCode(), e.getMessage()));
        }

        return ResponseEntity.status(e.getHttpStatus())
                .body(mapErrors(e.getErrorCode()));
    }

    @ExceptionHandler(WebClientResponseException.class)
    public ResponseEntity<String> handleWebClientResponseException(WebClientResponseException e) {
        log.error(EXCEPTION_WAS_THROWN, e);
        return ResponseEntity.status(e.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(e.getResponseBodyAsString());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<BaseErrorResponse> handleMethodArgumentNotValidException(
            MethodArgumentNotValidException e
    ) {
        log.error(EXCEPTION_WAS_THROWN, e);

        final List<FieldError> fieldErrors = e.getFieldErrors();
        final String[] errors = new String[fieldErrors.size()];

        for (int i = 0; i < fieldErrors.size(); i++) {
            final FieldError fieldError = fieldErrors.get(i);
            errors[i] = String.format("$.%s %s", fieldError.getField(), fieldError.getDefaultMessage());
        }

        return ResponseEntity.status(e.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(mapErrorCode(ErrorCode.BAD_REQUEST, errors));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<BaseErrorResponse> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException e
    ) {
        log.error(EXCEPTION_WAS_THROWN, e);

        return ResponseEntity.status(e.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(mapErrorCode(ErrorCode.BAD_REQUEST, e.getLocalizedMessage()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<BaseErrorResponse> handleNoResourceFoundException(
            NoResourceFoundException e
    ) {
        log.error(EXCEPTION_WAS_THROWN, e);

        return ResponseEntity.status(e.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(mapErrorCode(ErrorCode.BAD_REQUEST, e.getLocalizedMessage()));
    }

    private BaseErrorResponse mapErrors(ErrorCode... errorCodes) {
        return BaseErrorResponse.error(errorCodes,
                Arrays.stream(errorCodes).map(ErrorCode::getDescription).toList().toArray(new String[]{}));
    }

    private BaseErrorResponse mapErrorCode(final ErrorCode errorCode, String... errorMessages) {
        return BaseErrorResponse.error(new ErrorCode[]{errorCode}, errorMessages);
    }
}
