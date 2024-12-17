package com.Aura.Homes.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "notice_board")
@Data
public class NoticeBoard {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String content;
    private String date; // Date of notice


}
