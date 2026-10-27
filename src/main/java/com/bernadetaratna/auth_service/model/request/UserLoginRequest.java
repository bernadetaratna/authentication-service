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
public class UserLoginRequest implements Serializable {

    @NotBlank(message = "Email or Username should not be empty")
    private String identifier;

    @NotBlank(message = "Password is required")
    private String password;

}
