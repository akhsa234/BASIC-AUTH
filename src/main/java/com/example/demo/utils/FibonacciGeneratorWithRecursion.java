package com.example.demo.utils;

public class FibonacciGeneratorWithRecursion {

    private int generateFibonacciNumber(int n) {
        if (n <= 0) {
            return 0;
        }
        if (n == 1 || n == 2) {
            return 1;
        }
        return generateFibonacciNumber(n - 1) + generateFibonacciNumber(n - 2);
    }
}
