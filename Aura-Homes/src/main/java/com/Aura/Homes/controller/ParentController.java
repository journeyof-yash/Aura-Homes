package com.Aura.Homes.controller;

import com.Aura.Homes.entity.Parent;
import com.Aura.Homes.service.ParentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/parents")
public class ParentController {

    @Autowired
    private ParentService parentService;

    @GetMapping
    public ResponseEntity<List<Parent>> getAllParents() {
        return ResponseEntity.ok(parentService.getAllParents());
    }

    @GetMapping("/{email}")
    public ResponseEntity<Parent> getParent(@PathVariable String email) {
        return ResponseEntity.ok(parentService.getParentByEmail(email));
    }

    @PostMapping
    public ResponseEntity<Void> createParent(@RequestBody Parent parent) {
        parentService.saveParent(parent);
        return ResponseEntity.ok().build();
    }

}
