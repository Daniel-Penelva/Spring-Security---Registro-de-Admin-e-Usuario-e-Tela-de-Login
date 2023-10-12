package com.springsecurity.apitelalogin.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.springsecurity.apitelalogin.model.User;
import com.springsecurity.apitelalogin.repositories.UserRepository;

@Service
public class CustomUserDetailService implements UserDetailsService{

    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        User user = userRepository.findByEmail(username);

        if(user == null){
            throw new UsernameNotFoundException("user not found");
        }

        return new CustomUserDetail(user);
    }
    
}