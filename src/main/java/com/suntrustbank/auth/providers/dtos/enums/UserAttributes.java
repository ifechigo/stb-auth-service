package com.suntrustbank.auth.providers.dtos.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserAttributes {
    PHONE_NUMBER("phoneNumber"),
    ROLE("role");

    private final String value;
}
