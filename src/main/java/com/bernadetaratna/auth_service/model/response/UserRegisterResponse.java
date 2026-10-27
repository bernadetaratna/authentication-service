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
public class UserRegisterResponse implements Serializable {

    private String userId;
    private String email;
    private String userName;
    private String fullName;

}
