package com.suntrustbank.auth.providers.dtos.enums;

import lombok.Getter;

@Getter
public enum PublisherDetails {
    NOTIFICATION_EXCHANGE_NAME("notification.exchange"),
    SMS_ROUTING_KEY("sms");

    private final String value;

    PublisherDetails(String value) {
        this.value = value;
    }

}
