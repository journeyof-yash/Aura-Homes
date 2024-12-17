package com.Aura.Homes.service;

import com.Aura.Homes.entity.Student;
import com.Aura.Homes.repository.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentService {

    @Autowired
    private StudentRepository studentRepository;

    public List<Student> getAllStudents() {
        return studentRepository.findAll();
    }

    public Student getStudentByRegisterNumber(String registerNumber) {
        return studentRepository.findByRegisterNumber(registerNumber);
    }

    public void saveStudent(Student student) {
        studentRepository.save(student);
    }

}
