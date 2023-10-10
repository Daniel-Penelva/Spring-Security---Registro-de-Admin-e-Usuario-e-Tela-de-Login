package com.springsecurity.apitelalogin.service;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.model.User;

public interface UserService {
    
    User save(UserDto userDto);
}
