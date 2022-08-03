package com.magadiflo.app.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Martín"), new Student(2, "Gaspar"), new Student(3, "Alicia"),
            new Student(4, "Tinkler"), new Student(5, "Raúl"), new Student(6, "Abraham")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "/{studentId}")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println(studentId);
    }

    @PutMapping(path = "/{studentId}")
    public void updateStudent(@PathVariable Integer studentId, @RequestBody Student student) {
        System.out.println(String.format("%s %s", studentId, student));
    }

}
