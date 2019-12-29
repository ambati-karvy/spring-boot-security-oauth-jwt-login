package com.remote.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.remote.dto.UserWebDTO;

import java.util.List;

public interface UserService {

    List<UserWebDTO> getAllUsers();

    UserWebDTO getById(Long userId);

    UserWebDTO updateUser(UserWebDTO dto);

    UserWebDTO registerUser(UserWebDTO dto);

    void deleteUser(Long userId);
    
}
