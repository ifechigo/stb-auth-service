package com.suntrustbank.auth.core.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


@Slf4j
@Getter
@Configuration
public class AESEncryptionUtils {

    private static final String AES_ALGORITHM = "AES";
    private static final String PWH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Derive AES Key from a Passphrase
    private static SecretKey deriveKey(String passphrase, String salt) throws GenericErrorCodeException {
        try {
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt.getBytes(), 65536, 128);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(PWH_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, AES_ALGORITHM);
        } catch (Exception e) {
            log.info("Error Generating key:: {}", e.getMessage(), e);
            throw GenericErrorCodeException.badRequest("failed to derive key");
        }
    }

    public static String encrypt(String passphrase, String salt, Object data) throws GenericErrorCodeException {
        SecretKey key = deriveKey(passphrase, salt);
        try {
            String jsonData = (data instanceof String)
                    ? (String) data
                    : OBJECT_MAPPER.writeValueAsString(data);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(jsonData.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            log.info("Error Encrypting data:: {}", e.getMessage(), e);
            throw GenericErrorCodeException.serverError();
        }
    }

    public static <T> T decrypt(String passphrase, String salt, String encryptedData, Class<T> targetType) throws GenericErrorCodeException {
        SecretKey key = deriveKey(passphrase, salt);
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            String decryptedString = new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);

            if (isValidJson(decryptedString)) {
                return OBJECT_MAPPER.readValue(decryptedString, targetType);
            } else {
                return (T) decryptedString;
            }
        } catch (Exception e) {
            log.info("Error Decrypting data:: {}", e.getMessage(), e);
            throw GenericErrorCodeException.badRequest("invalid request");
        }
    }

    private static boolean isValidJson(String data) {
        try {
            OBJECT_MAPPER.readTree(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}