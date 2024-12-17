package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;

@Entity
@Table(name = "attendance")
@Data
public class Attendance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String studentRegisterNumber; // Foreign key reference to Student
    private Date date;
    private String status; // Present, Absent, Leave


}
