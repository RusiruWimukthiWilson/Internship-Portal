package com.portal.internship.controller;

import com.portal.internship.dto.RegisterRequest;
import com.portal.internship.model.Role;
import com.portal.internship.model.User;
import com.portal.internship.repository.RoleRepository;
import com.portal.internship.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest());
        return "auth/register";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute("registerRequest") RegisterRequest request,
                               BindingResult result, Model model) {

        if (userRepository.existsByEmail(request.getEmail())) {
            result.rejectValue("email", "error.user", "An account with this email already exists.");
        }

        if (result.hasErrors()) {
            return "auth/register";
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        Set<Role> roles = new HashSet<>();
        String targetRole = "ROLE_" + request.getRole().toUpperCase();
        Role userRole = roleRepository.findByName(targetRole)
                .orElseThrow(() -> new RuntimeException("Error: System target Role was not found."));
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);
        return "redirect:/login?registered=true";
    }

    @GetMapping("/profile")
    public String showUserProfile(Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }
        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        model.addAttribute("user", user);
        return "auth/profile";
    }
}
