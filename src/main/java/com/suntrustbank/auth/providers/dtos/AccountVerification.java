package com.suntrustbank.auth.providers.dtos;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AccountVerification {
    private String password;
    private boolean isResendEmailLink;
}
