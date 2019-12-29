package com.remote.repository;


import org.springframework.data.repository.CrudRepository;

import com.remote.model.User;

public interface UserRepository extends CrudRepository<User, Long> {
	User findUserByEmail( String email );
}
