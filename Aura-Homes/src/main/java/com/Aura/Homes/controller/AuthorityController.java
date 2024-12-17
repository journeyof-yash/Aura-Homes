package com.Aura.Homes.controller;

import com.Aura.Homes.entity.Authority;
import com.Aura.Homes.service.AuthorityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/authorities")
public class AuthorityController {

    @Autowired
    private AuthorityService authorityService;

    @GetMapping
    public ResponseEntity<List<Authority>> getAllAuthorities() {
        return ResponseEntity.ok(authorityService.getAllAuthorities());
    }

    @PostMapping
    public ResponseEntity<Void> createAuthority(@RequestBody Authority authority) {
        authorityService.saveAuthority(authority);
        return ResponseEntity.ok().build();
    }

}
