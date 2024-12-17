package com.Aura.Homes.controller;

import com.Aura.Homes.entity.Student;
import com.Aura.Homes.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/students")
public class StudentController {

    @Autowired
    private StudentService studentService;

    @GetMapping
    public ResponseEntity<List<Student>> getAllStudents() {
        return ResponseEntity.ok(studentService.getAllStudents());
    }

    @GetMapping("/{registerNumber}")
    public ResponseEntity<Student> getStudent(@PathVariable String registerNumber) {
        return ResponseEntity.ok(studentService.getStudentByRegisterNumber(registerNumber));
    }

    @PostMapping
    public ResponseEntity<Void> createStudent(@RequestBody Student student) {
        studentService.saveStudent(student);
        return ResponseEntity.ok().build();
    }


}
