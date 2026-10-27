package com.bernadetaratna.auth_service.util;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CommonUtils {

    private CommonUtils() {
    }

    public static String generateRandomUUID() {
        return UUID.randomUUID().toString();
    }

}
