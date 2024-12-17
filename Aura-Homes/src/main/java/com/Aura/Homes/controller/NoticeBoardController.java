package com.Aura.Homes.controller;

import com.Aura.Homes.entity.NoticeBoard;
import com.Aura.Homes.service.NoticeBoardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notice-board")
public class NoticeBoardController {

    @Autowired
    private NoticeBoardService noticeBoardService;

    @GetMapping
    public ResponseEntity<List<NoticeBoard>> getAllNotices() {
        return ResponseEntity.ok(noticeBoardService.getAllNotices());
    }

    @PostMapping
    public ResponseEntity<Void> createNotice(@RequestBody NoticeBoard notice) {
        noticeBoardService.saveNotice(notice);
        return ResponseEntity.ok().build();
    }

}
