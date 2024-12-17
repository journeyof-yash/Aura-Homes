package com.Aura.Homes.controller;

import com.Aura.Homes.entity.MessMenu;
import com.Aura.Homes.service.MessMenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/mess-menu")
public class MessMenuController {

    @Autowired
    private MessMenuService messMenuService;

    @GetMapping
    public ResponseEntity<List<MessMenu>> getAllMenus() {
        return ResponseEntity.ok(messMenuService.getAllMenus());
    }

    @PostMapping
    public ResponseEntity<Void> createMenu(@RequestBody MessMenu menu) {
        messMenuService.saveMenu(menu);
        return ResponseEntity.ok().build();
    }

}
