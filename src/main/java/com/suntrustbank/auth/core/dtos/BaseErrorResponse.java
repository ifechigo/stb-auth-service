package com.suntrustbank.auth.core.dtos;


import com.suntrustbank.auth.core.enums.BaseResponseStatus;
import com.suntrustbank.auth.core.enums.ErrorCode;
import lombok.Builder;
import lombok.Generated;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@Generated
public class BaseErrorResponse {

    private BaseResponseStatus status;
    private ErrorCode[] errors;
    private String[] messages;

    public static BaseErrorResponse error(final ErrorCode[] errorCodes, final String[] errorMessages) {
        return BaseErrorResponse.builder()
                .errors(errorCodes)
                .messages(errorMessages)
                .status(BaseResponseStatus.ERROR)
                .build();
    }

    public static BaseErrorResponse error(final ErrorCode errorCode, final String errorMessage) {
        return BaseErrorResponse.builder()
                .errors(new ErrorCode[]{errorCode})
                .messages(new String[]{errorMessage})
                .status(BaseResponseStatus.ERROR)
                .build();
    }

    public static BaseErrorResponse error(final ErrorCode errorCode) {
        return error(errorCode, errorCode.getDescription());
    }
}
