package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "hana stuarts"),
            new Student(2, "sara eeeee"),
            new Student(3, "sahar wwwww"),
            new Student(4, "reza tttt")
    );

    @GetMapping
    public List<Student> getAll() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {

        System.out.println("method is registerNewStudent");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {

        System.out.println("method is deleteStudent");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId
            , @RequestBody Student student) {

        System.out.println("method is updateStudent");
        System.out.println(String.format("%s %d", student, studentId));
        //System.out.println(String.format("%s ",studentId));
    }
}
