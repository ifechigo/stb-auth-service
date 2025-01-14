package com.suntrustbank.auth.providers.entrypoints;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.jwt.JwtUtil;
import com.suntrustbank.auth.providers.dtos.*;
import com.suntrustbank.auth.providers.services.AdminAccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import static com.suntrustbank.auth.core.constants.Common.USER_NAME;

@RestController
@RequestMapping("/v1/auth/admin")
@RequiredArgsConstructor
public class AdminAuthenticationUserController {

    private final AdminAccountService adminAccountService;
    private final JwtUtil jwtService;

    @PostMapping("/signup")
    public ResponseEntity createUser(@RequestBody @Validated AuthAdminCreationRequest authCreationRequest) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.createUser(authCreationRequest));
    }

    @PostMapping("/token")
    public BaseResponse authenticate(@RequestBody @Validated EncryptedRequest request) throws GenericErrorCodeException {
        return adminAccountService.loginUser(request);
    }


    @PutMapping("/update/email/{email}")
    public ResponseEntity verifyEmail(@RequestHeader("Authorization") String authorizationHeader,
                                      @PathVariable String email) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.updateEmail(userId, email));
    }

    @PutMapping("/update/profile")
    public ResponseEntity update(@RequestHeader("Authorization") String authorizationHeader,
                                 @RequestBody UpdateRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.update(userId, requestDto));
    }

    @PutMapping("/update/password")
    public ResponseEntity updatePassword(@RequestHeader("Authorization") String authorizationHeader,
                                    @RequestBody @Validated UpdatePasswordRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.updatePassword(userId, requestDto));
    }


    @PostMapping("/password-reset")
    public ResponseEntity resetPassword(@RequestBody @Validated ResetRequest resetRequestDto) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.passwordReset(resetRequestDto));
    }

    @PostMapping("/password-reset/verify")
    public ResponseEntity verifyPasswordUpdate(@RequestBody @Validated ResetOtpRequest resetOtpRequest) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.verifyPasswordResetOtp(resetOtpRequest));
    }

    @PutMapping("/password-reset")
    public ResponseEntity saveNewPassword(@RequestBody @Validated PasswordUpdateRequest pinUpdateRequestDto) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.saveNewPassword(pinUpdateRequestDto));
    }
}
