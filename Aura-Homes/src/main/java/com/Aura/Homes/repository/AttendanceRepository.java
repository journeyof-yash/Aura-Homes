package com.Aura.Homes.repository;

import com.Aura.Homes.entity.Attendance;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AttendanceRepository extends JpaRepository<Attendance, Long> {

    List<Attendance> findByStudentRegisterNumber(String registerNumber);
}
