package com.Aura.Homes.service;

import com.Aura.Homes.entity.RoomCleaning;
import com.Aura.Homes.repository.RoomCleaningRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoomCleaningService {

    @Autowired
    private RoomCleaningRepository roomCleaningRepository;

    public List<RoomCleaning> getAllRoomCleanings() {
        return roomCleaningRepository.findAll();
    }

    public void saveRoomCleaning(RoomCleaning roomCleaning) {
        roomCleaningRepository.save(roomCleaning);
    }

}
