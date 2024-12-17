package com.Aura.Homes.controller;

import com.Aura.Homes.entity.Attendance;
import com.Aura.Homes.service.AttendanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/attendance")
public class AttendanceController {

    @Autowired
    private AttendanceService attendanceService;

    @GetMapping("/{registerNumber}")
    public ResponseEntity<List<Attendance>> getAttendance(@PathVariable String registerNumber) {
        return ResponseEntity.ok(attendanceService.getAttendanceByStudentRegisterNumber(registerNumber));
    }

    @PostMapping
    public ResponseEntity<Void> createAttendance(@RequestBody Attendance attendance) {
        attendanceService.saveAttendance(attendance);
        return ResponseEntity.ok().build();
    }

}
