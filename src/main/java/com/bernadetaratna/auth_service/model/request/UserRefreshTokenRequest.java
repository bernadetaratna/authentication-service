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
public class UserRefreshTokenRequest implements Serializable {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;

}
