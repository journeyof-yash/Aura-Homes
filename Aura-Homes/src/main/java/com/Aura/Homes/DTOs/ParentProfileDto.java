package com.Aura.Homes.DTOs;

import lombok.Data;

@Data
public class ParentProfileDto {
    private Long id;
    private String name;
    private String email;
    private String phoneNumber;
    private String relationship; // e.g., Father, Mother
    private String studentRegisterNumber; // Foreign key reference to Student

}
