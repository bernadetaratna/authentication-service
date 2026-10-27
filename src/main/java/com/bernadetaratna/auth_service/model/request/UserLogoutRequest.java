package com.bernadetaratna.auth_service.model.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserLogoutRequest implements Serializable {

    @NotBlank(message = "Refresh Token is required")
    private String refreshToken;

}
