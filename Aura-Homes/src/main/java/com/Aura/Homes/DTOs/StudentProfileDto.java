package com.Aura.Homes.DTOs;

import lombok.Data;

@Data
public class StudentProfileDto {
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
