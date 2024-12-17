package com.Aura.Homes.repository;

import com.Aura.Homes.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentRepository extends JpaRepository<Student, Long> {

    Student findByRegisterNumber(String registerNumber);

}
