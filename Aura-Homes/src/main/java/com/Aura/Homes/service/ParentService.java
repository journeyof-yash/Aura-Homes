package com.Aura.Homes.service;

import com.Aura.Homes.entity.Parent;
import com.Aura.Homes.repository.ParentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ParentService {

    @Autowired
    private ParentRepository parentRepository;

    public List<Parent> getAllParents() {
        return parentRepository.findAll();
    }

    public Parent getParentByEmail(String email) {
        return parentRepository.findByEmail(email);
    }

    public void saveParent(Parent parent) {
        parentRepository.save(parent);
    }

}
