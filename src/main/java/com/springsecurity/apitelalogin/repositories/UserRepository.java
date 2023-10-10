package com.springsecurity.apitelalogin.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springsecurity.apitelalogin.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{
    
}
