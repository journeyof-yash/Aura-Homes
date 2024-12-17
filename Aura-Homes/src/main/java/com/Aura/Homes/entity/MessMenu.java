package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "mess_menu")
@Data
public class MessMenu {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String month;
    private String week;
    private String breakfast;
    private String lunch;
    private String snacks;
    private String dinner;

}
