package com.security.dto;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.hibernate.validator.constraints.NotBlank;

@Getter
@Setter
public class JoinForm {

    @NotBlank(message = "이름을 입력해주시기 바랍니다.")
    private String username;

    @NotBlank(message = "비밀번호를 입력해주시기 바랍니다.")
    private String password;

    @NotBlank(message = "비밀번호 확인을 입력해주시기 바랍니다.")
    private String passwordConfirm;
}