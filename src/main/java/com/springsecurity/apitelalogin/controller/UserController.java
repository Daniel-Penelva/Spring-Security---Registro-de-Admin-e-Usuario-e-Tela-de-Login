package com.springsecurity.apitelalogin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.service.UserService;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    // http://localhost:8080/registration
    @GetMapping("/registration")
    public String getRegistrationPage(@ModelAttribute("user") UserDto userDto) {
        return "register";
    }

    // http://localhost:8080/registration
    @PostMapping("/registration")
    public String saveUser(@ModelAttribute("user") UserDto userDto, Model model) {

        userService.save(userDto);
        model.addAttribute("message", "Registered Successfuly");

        return "register";
    }

    // http://localhost:8080/login
    @GetMapping("/login")
    public String login(){
        return "login";
    }

}
