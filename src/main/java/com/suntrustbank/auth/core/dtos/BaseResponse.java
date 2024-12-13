package com.suntrustbank.auth.core.dtos;


import com.suntrustbank.auth.core.enums.BaseResponseMessage;
import com.suntrustbank.auth.core.enums.BaseResponseStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Generated;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@Builder
@Generated
@NoArgsConstructor
@AllArgsConstructor
public class BaseResponse<T> {

    private BaseResponseStatus status;
    private T data;
    private String message;

    public static <T> BaseResponse<T> success(final T data, final BaseResponseMessage baseResponseMessage) {
        return BaseResponse.<T>builder()
                .data(data)
                .message(baseResponseMessage.getValue())
                .status(BaseResponseStatus.SUCCESS)
                .build();
    }

    public static <T> BaseResponse<T> error(final BaseResponseMessage baseResponseMessage) {
        return BaseResponse.<T>builder()
                .message(baseResponseMessage.getValue())
                .status(BaseResponseStatus.ERROR)
                .build();
    }
}
