package com.bernadetaratna.auth_service.model.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRefreshTokenResponse implements Serializable {

    private String accessToken;
    private String tokenType;
    private String expiredTime;
    private Integer expiresIn;

}
