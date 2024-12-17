package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "parents")
@Data
public class Parent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String email;
    private String phoneNumber;
    private String relationship; // e.g., Father, Mother
    private String studentRegisterNumber; // Foreign key reference to Student

}
