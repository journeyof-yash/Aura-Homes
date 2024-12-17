package com.Aura.Homes.service;

import com.Aura.Homes.entity.Attendance;
import com.Aura.Homes.repository.AttendanceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AttendanceService {

    @Autowired
    private AttendanceRepository attendanceRepository;

    public List<Attendance> getAttendanceByStudentRegisterNumber(String registerNumber) {
        return attendanceRepository.findByStudentRegisterNumber(registerNumber);
    }

    public void saveAttendance(Attendance attendance) {
        attendanceRepository.save(attendance);
    }

}
