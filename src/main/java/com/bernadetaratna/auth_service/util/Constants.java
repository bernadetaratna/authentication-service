package com.bernadetaratna.auth_service.util;

import org.springframework.stereotype.Component;

@Component
public class Constants {

    private Constants() {
    }

    public static final String SHA_256 = "SHA-256";

    public static final String USER_ROLE = "USER";

    public static final String BEARER_TOKEN_TYPE = "Bearer";

}
