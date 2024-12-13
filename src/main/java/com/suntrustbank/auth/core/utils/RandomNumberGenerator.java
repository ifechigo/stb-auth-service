package com.suntrustbank.auth.core.utils;

import java.util.Random;

public class RandomNumberGenerator {

    private static final int UPPER_BOUND = 100000;
    private static final int LOWER_BOUND = 900000;

    /**
     * generates a 6 digits code
     *
     * @return
     */
    public static String generateOTP() {
        Random random = new Random();
        return String.format("%s", random.nextInt(LOWER_BOUND) + UPPER_BOUND);
    }
}
