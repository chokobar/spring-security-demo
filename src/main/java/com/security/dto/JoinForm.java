package com.security.dto;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@Getter
@Setter
public class JoinForm {

    @NonNull
    private String username;

    @NonNull
    private String password;

    @NonNull
    private String passwordConfirm;
}