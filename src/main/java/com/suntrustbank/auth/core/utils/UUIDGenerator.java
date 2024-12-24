package com.suntrustbank.auth.core.utils;

import org.springframework.util.StringUtils;

import java.util.UUID;

public class UUIDGenerator {

    public static String generate() {
        return StringUtils.replace(UUID.randomUUID().toString(), "-", "");
    }
}
