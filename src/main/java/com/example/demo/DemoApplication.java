package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Scanner;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);

        int previousNum = 1;
        int secondPreviousNum = 0;

        System.out.println("************** Generating Fibonacci Series with loop *****************");
        System.out.println("Enter number upto which Fibonacci series to print: ");

        int number = new Scanner(System.in).nextInt();

        for (int i = 1; i <= number; i++) {
            if (i == 1) {
                System.out.print("0 ");
            } else if (i == 2 || i == 3) {
                secondPreviousNum = 1;
                previousNum = 1;
                System.out.print(" 1");
            } else {
                int fibonacciNum = previousNum + secondPreviousNum;
                System.out.print(fibonacciNum + " ");
                secondPreviousNum = previousNum;
                previousNum = fibonacciNum;
            }
        }
    }

}
