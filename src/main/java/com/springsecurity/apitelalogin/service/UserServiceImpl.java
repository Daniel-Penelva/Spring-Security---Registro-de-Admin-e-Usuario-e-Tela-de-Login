package com.springsecurity.apitelalogin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.model.User;
import com.springsecurity.apitelalogin.repositories.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User save(UserDto userDto) {

        User user = new User(userDto.getEmail(), userDto.getPassword(), userDto.getRole(), userDto.getFullname());
        return userRepository.save(user);
    }

}
