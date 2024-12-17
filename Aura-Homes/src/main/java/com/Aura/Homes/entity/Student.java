package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "students")
@Data
public class Student {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String registerNumber;
    private String name;
    private String dob; // Date of Birth
    private String gender;
    private String email;
    private String phoneNumber;
    private String address;
    private String course;
    private String yearOfStudy;

}
