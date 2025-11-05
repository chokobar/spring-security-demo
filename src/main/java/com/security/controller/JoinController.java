package com.security.controller;

import com.security.dto.JoinForm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import jakarta.validation.Valid;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class JoinController {

    //private final InMemoryUserDetailsManager userDetailsManager;
    private final org.springframework.security.provisioning.UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/join")
    public String joinForm(Model model) {
        model.addAttribute("joinForm", new JoinForm());
        return "join";
    }

    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinForm joinForm, BindingResult bindingResult, RedirectAttributes ra) {

        if (bindingResult.hasErrors()) {
            return "join";
        }

        if (!joinForm.getPassword().equals(joinForm.getPasswordConfirm())) {
            bindingResult.rejectValue("passwordConfirm", "mismatch", "비밀번호가 일치하지 않습니다.");
            return "join";
        }
        if (userDetailsManager.userExists(joinForm.getUsername())) {
            bindingResult.rejectValue("username", "duplicate", "이미 존재하는 아이디입니다.");
            return "join";
        }

        UserDetails newUser = User.withUsername(joinForm.getUsername())
                .password(passwordEncoder.encode(joinForm.getPassword())) //  BCrypt
                .roles("USER")
                .build();

        userDetailsManager.createUser(newUser);

        ra.addFlashAttribute("joined", true);
        return "redirect:/auth/login";
    }
}
