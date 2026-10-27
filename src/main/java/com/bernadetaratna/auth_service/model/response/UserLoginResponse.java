package com.bernadetaratna.auth_service.model.response;

import lombok.Data;

@Data
public class UserLoginResponse extends UserRefreshTokenResponse {

    private String refreshToken;

}
