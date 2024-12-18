package com.suntrustbank.auth.providers.dtos;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class SmsRequest {
    private String from;
    private String to;
    private String smsType;
    private String body;
}
