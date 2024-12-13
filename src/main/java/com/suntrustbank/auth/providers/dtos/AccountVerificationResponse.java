package com.suntrustbank.auth.providers.dtos;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Builder
public class AccountVerificationResponse {
    private long expiresIn;

    private String referenceId;
}
