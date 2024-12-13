package com.suntrustbank.auth.providers.entrypoints;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.jwt.JwtUtil;
import com.suntrustbank.auth.providers.services.AccountService;
import com.suntrustbank.auth.providers.dtos.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import static com.suntrustbank.auth.core.constants.Common.EMAIL;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;
    private final JwtUtil jwtService;

    @PostMapping("/signup")
    public ResponseEntity createUser(@RequestBody @Validated AuthCreationRequest authCreationRequest) throws GenericErrorCodeException {
        return ResponseEntity.ok(accountService.createUser(authCreationRequest));
    }

    @GetMapping("/verify/email/{reference}")
    public ResponseEntity verifyEmail(@PathVariable String reference) throws GenericErrorCodeException {
        return ResponseEntity.ok(accountService.verifyEmail(reference));
    }

    @PostMapping("/update/phone/{phoneNumber}")
    public ResponseEntity<BaseResponse<?>> updatePhoneNumber(@RequestHeader("Authorization") String authorizationHeader,
                                                      @PathVariable String phoneNumber) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, EMAIL).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        accountService.updatePhoneNumber(userId, phoneNumber);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/verify/phone/{otp}")
    public ResponseEntity verifyPhoneNumber(@RequestHeader("Authorization") String authorizationHeader,
                                                             @PathVariable String otp) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, EMAIL).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(accountService.verifyPhoneNumber(userId, otp));
    }

    @PostMapping("/resend-email")
    public ResponseEntity verifyEmail(@RequestBody @Validated VerifyEmailRequest requestDto) throws GenericErrorCodeException {
        return ResponseEntity.ok(accountService.resendVerifyEmailLink(requestDto));
    }

    @PostMapping("/password-reset")
    public ResponseEntity resetPassword(@RequestBody @Validated PasswordResetRequest passwordResetRequestDto) {
        accountService.passwordReset(passwordResetRequestDto);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/verify/password-reset")
    public ResponseEntity verifyPasswordUpdate(@RequestBody @Validated PasswordUpdateRequest passwordUpdateRequestDto)
            throws GenericErrorCodeException {
        return ResponseEntity.ok(accountService.verifyPasswordReset(passwordUpdateRequestDto));
    }

    @PutMapping("/update")
    public ResponseEntity update(@RequestHeader("Authorization") String authorizationHeader,
                                                  @RequestBody UpdateRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, EMAIL).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(accountService.update(userId, requestDto));
    }

    @PutMapping("/update/password")
    public ResponseEntity updatePassword(@RequestHeader("Authorization") String authorizationHeader,
                                                          @RequestBody @Validated UpdatePasswordRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, EMAIL).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(accountService.updatePassword(userId, requestDto));
    }
}
