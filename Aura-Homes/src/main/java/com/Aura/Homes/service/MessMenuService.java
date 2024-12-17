package com.Aura.Homes.service;

import com.Aura.Homes.entity.MessMenu;
import com.Aura.Homes.repository.MessMenuRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MessMenuService {

    @Autowired
    private MessMenuRepository messMenuRepository;


    public List<MessMenu> getAllMenus() {
        return messMenuRepository.findAll();
    }

    public void saveMenu(MessMenu menu) {
        messMenuRepository.save(menu);
    }

}
