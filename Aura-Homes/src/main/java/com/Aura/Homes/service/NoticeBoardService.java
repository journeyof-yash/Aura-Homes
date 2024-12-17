package com.Aura.Homes.service;

import com.Aura.Homes.entity.NoticeBoard;
import com.Aura.Homes.repository.NoticeBoardRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoticeBoardService {

    @Autowired
    private NoticeBoardRepository noticeBoardRepository;

    public List<NoticeBoard> getAllNotices() {
        return noticeBoardRepository.findAll();
    }

    public void saveNotice(NoticeBoard notice) {
        noticeBoardRepository.save(notice);
    }

}
