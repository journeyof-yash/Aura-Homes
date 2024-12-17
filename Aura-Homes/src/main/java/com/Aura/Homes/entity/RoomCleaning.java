package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "room_cleaning")
@Data
public class RoomCleaning {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String roomNumber;
    private String cleaningStatus; // Cleaned, Not Cleaned


}
