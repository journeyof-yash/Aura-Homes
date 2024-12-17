package com.Aura.Homes.service;

import com.Aura.Homes.entity.Authority;
import com.Aura.Homes.repository.AuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthorityService {

    @Autowired
    private AuthorityRepository authorityRepository;

    public List<Authority> getAllAuthorities() {
        return authorityRepository.findAll();
    }

    public void saveAuthority(Authority authority) {
        authorityRepository.save(authority);
    }

}
