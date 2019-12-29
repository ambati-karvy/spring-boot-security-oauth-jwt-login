package com.remote.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.remote.model.Privilege;

public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {

    Privilege findByName(String name);

    void delete(Privilege privilege);

}
