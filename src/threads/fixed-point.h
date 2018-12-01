//
// Created by meritv on 11/26/18.
//

#ifndef PINTOS_OPERATING_SYSTEM_FIXED_POINT_H
#define PINTOS_OPERATING_SYSTEM_FIXED_POINT_H

#endif //PINTOS_OPERATING_SYSTEM_FIXED_POINT_H
/*
 * The implementation of the fixed point real arithmetic operations.
 * x and y are fixed-point numbers, n is an integer, fixed-point numbers
 * are in signed p.q format where p + q = 31, and f is 1 << q
 */

#define F (1 << 14)     /* 17.14 format */


int convert_int_to_fp(int n) {
    return n * F;
}

int convert_fp_to_int(int x) {
    return x / F;
}

int convert_fp_to_int_rounding(int x) {
    if (x >= 0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
}

int add_fp(int x, int y) {
    return x + y;
}

int subtract_fp(int x, int y) {
    return x - y;
}

int add_int_to_fp(int n, int x) {
    return x + n * F;
}

int subtract_int_from_fp(int n, int x) {
    return x - n * F;
}

int multiply_fp(int x, int y) {
    return ((int64_t) x) * y / F;
}

int multiply_int_by_fp(int n, int x) {
    return x * n;
}

int divide_fp(int x, int y) {
    return ((int64_t) x) * F / y;
}

int divide_fp_by_int(int x, int n) {
    return x / n;
}