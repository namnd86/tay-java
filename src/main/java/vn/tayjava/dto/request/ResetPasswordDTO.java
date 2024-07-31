package vn.tayjava.dto.request;

import vn.tayjava.exception.InvalidDataException;

public record ResetPasswordDTO(String secretKey, String password, String confirmPassword) {
    public ResetPasswordDTO {
        if (!password.equals(confirmPassword)) {
            throw new InvalidDataException("Password not match");
        }
    }
}
