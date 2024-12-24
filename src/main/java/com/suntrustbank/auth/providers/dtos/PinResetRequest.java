package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.Generated;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Generated
public class PinResetRequest {
    @Email(message = "Invalid email format")
    private String email;

    @Pattern(regexp = "\\d{10}", message = "phone number field must be exactly 10 digits")
    private String phoneNumber;

    @AssertTrue(message = "Either email or phone number field must be provided")
    public boolean isEmailOrPhoneProvided() {
        return (email != null && !email.isBlank()) || (phoneNumber != null && !phoneNumber.isBlank());
    }
}
