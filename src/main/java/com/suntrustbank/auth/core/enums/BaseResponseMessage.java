package com.suntrustbank.auth.core.enums;

import lombok.Generated;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Generated
@RequiredArgsConstructor
public enum BaseResponseMessage {

    SUCCESSFUL("success"),
    FAILED("failed");

    private final String value;
}
