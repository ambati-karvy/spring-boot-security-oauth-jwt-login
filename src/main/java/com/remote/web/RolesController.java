package com.remote.web;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.remote.dto.RoleDTO;
import com.remote.service.RoleService;

import java.util.List;

@RestController
@RequestMapping( "/rest/roles" )
public class RolesController {

    @Autowired
    private RoleService roleService;

    @CrossOrigin
    @PreAuthorize("hasAuthority('RIGHT_EDIT_USERS')")
    @RequestMapping( value = "/all", method = RequestMethod.GET )
    public ResponseEntity<List<RoleDTO>> getAll() {
        List<RoleDTO> roleDTOs = roleService.getAllRoles();
        if ( roleDTOs!= null ) {
            return new ResponseEntity<>( roleDTOs, HttpStatus.OK );
        } else {
            return new ResponseEntity<>( HttpStatus.NOT_FOUND );
        }
    }

    
}
