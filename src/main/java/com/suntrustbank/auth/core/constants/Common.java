package com.suntrustbank.auth.core.constants;

import lombok.Getter;

@Getter
public class Common {
    public static final int PIN_LENGTH = 4;
    public static final int OTP_EXPIRY_DURATION = 3;
    public static final String BEARER = "Bearer";
    public static final String UPDATED = "updated";
    public static final String RESET_PIN = "rp_";
    public static final String USER_NAME = "preferred_username";
    public static final String LOGIN_USER = "loginUser";
    public static final String OTP = "otp";
    public static final String DEFAULT_OTP = "000111";
    public static final String PRODUCTION = "prod";
    public static final String STAGING = "staging";


//    public static final String SENDER_EMAIL = "no-reply@getrova.com";
//    public static final String VERIFY_OTP = "Verify OTP";
//    public static final String WELCOME_TO_BAAS = "Welcome to SunTrust";
//    public static final String RESEND_EMAIL = "rs";
//    public static final int RESEND_EMAIL_REFERENCE_LENGTH = 3;
//    public static final String EMAIL = "email";
//    public static final String USER_ID = "userId";
//    public static final String PIN = "pin";
//    public static final String PHONE = "phone_";
}
