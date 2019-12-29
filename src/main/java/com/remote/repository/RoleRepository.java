package com.remote.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.remote.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByName(String name);

    void delete(Role role);

}
