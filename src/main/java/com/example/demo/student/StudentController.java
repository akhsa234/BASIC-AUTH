package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/student")
public class StudentController {

    private final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "hana stuarts"),
            new Student(2, "sara eeeee"),
            new Student(3, "sahar wwwww"),
            new Student(4, "reza tttt")
    );



@GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable Integer studentId)  {
    return STUDENTS.stream()
            .filter(student -> studentId.equals(student.getStudentId()))
            .findFirst()
            .orElseThrow(()-> new IllegalStateException("Student " + studentId + "does not exist"));

    }
}
