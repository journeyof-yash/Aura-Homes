package com.Aura.Homes.controller;

import com.Aura.Homes.entity.RoomCleaning;
import com.Aura.Homes.service.RoomCleaningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/room-cleaning")
public class RoomCleaningController {

    @Autowired
    private RoomCleaningService roomCleaningService;

    @GetMapping
    public ResponseEntity<List<RoomCleaning>> getAllRoomCleanings() {
        return ResponseEntity.ok(roomCleaningService.getAllRoomCleanings());
    }

    @PostMapping
    public ResponseEntity<Void> createRoomCleaning(@RequestBody RoomCleaning roomCleaning) {
        roomCleaningService.saveRoomCleaning(roomCleaning);
        return ResponseEntity.ok().build();
    }

}
