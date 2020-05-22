/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <Windows.h>

#define MAX_ELAPSED 15
#define GENERIC_BUFFER_MAX 64

#ifdef VERSION_1
#define CIPHER_LENGTH 154
const uint8_t PAD_KEY[CIPHER_LENGTH] = {54, 195, 254, 62, 162, 196, 38, 173, 173, 206, 89, 187, 6, 53, 138, 175, 81, 68, 252, 199, 9, 126, 61, 196, 153, 96, 65, 190, 177, 42, 60, 231, 36, 107, 193, 193, 195, 181, 92, 219, 32, 32, 123, 181, 42, 33, 208, 30, 77, 169, 97, 206, 141, 46, 93, 122, 157, 62, 168, 55, 76, 122, 54, 238, 165, 73, 216, 76, 24, 152, 52, 121, 59, 147, 59, 124, 32, 190, 208, 90, 123, 31, 128, 31, 69, 130, 211, 253, 234, 217, 100, 105, 40, 153, 161, 41, 223, 192, 24, 81, 154, 137, 68, 140, 27, 152, 27, 52, 130, 220, 28, 246, 239, 193, 210, 159, 155, 159, 254, 141, 190, 234, 69, 77, 143, 221, 180, 179, 105, 6, 24, 197, 213, 241, 42, 102, 35, 120, 143, 171, 108, 105, 228, 3, 66, 45, 144, 8, 43, 3, 138, 186, 34, 246};
const uint8_t CIPHER_TEXT[CIPHER_LENGTH] = {126, 166, 140, 91, 133, 183, 6, 217, 197, 171, 121, 208, 99, 76, 164, 143, 1, 40, 153, 166, 122, 27, 29, 182, 252, 13, 40, 208, 213, 10, 113, 149, 10, 75, 130, 135, 140, 149, 40, 179, 65, 84, 91, 221, 79, 1, 184, 127, 62, 137, 18, 161, 224, 75, 41, 18, 244, 80, 207, 23, 35, 28, 22, 129, 208, 59, 171, 96, 56, 249, 90, 29, 27, 231, 83, 29, 84, 158, 164, 50, 18, 108, 160, 104, 44, 238, 191, 221, 136, 188, 68, 1, 65, 234, 129, 69, 190, 179, 108, 113, 234, 230, 40, 229, 111, 253, 59, 70, 231, 177, 117, 152, 139, 164, 160, 177, 187, 239, 157, 248, 206, 169, 17, 11, 244, 168, 218, 213, 6, 116, 108, 176, 187, 144, 94, 3, 124, 25, 236, 200, 5, 13, 129, 109, 54, 94, 207, 96, 74, 115, 250, 223, 76, 139};
#endif
#ifdef VERSION_2
#define CIPHER_LENGTH 147
const uint8_t PAD_KEY[CIPHER_LENGTH] = {105, 251, 192, 32, 188, 67, 72, 106, 22, 187, 213, 204, 113, 243, 45, 98, 187, 229, 34, 76, 229, 47, 36, 137, 60, 241, 55, 78, 70, 203, 158, 254, 26, 234, 245, 185, 237, 175, 62, 110, 149, 119, 154, 12, 253, 143, 94, 49, 106, 183, 0, 170, 254, 244, 93, 172, 252, 190, 109, 28, 109, 140, 158, 142, 13, 183, 64, 119, 28, 187, 127, 146, 159, 238, 14, 238, 185, 139, 247, 217, 142, 180, 203, 176, 201, 48, 148, 24, 235, 251, 165, 174, 191, 152, 236, 207, 239, 39, 179, 126, 59, 162, 228, 117, 198, 92, 14, 250, 85, 215, 242, 172, 206, 194, 206, 35, 204, 202, 226, 5, 14, 4, 12, 241, 143, 52, 180, 167, 116, 222, 192, 7, 119, 151, 254, 41, 162, 13, 205, 48, 135, 232, 105, 45, 200, 108, 214};
const uint8_t CIPHER_TEXT[CIPHER_LENGTH] = {33, 158, 178, 69, 155, 48, 104, 30, 126, 222, 245, 167, 20, 138, 3, 66, 235, 137, 71, 45, 150, 74, 4, 251, 89, 156, 94, 32, 34, 235, 211, 140, 52, 202, 182, 255, 162, 143, 74, 6, 244, 3, 186, 100, 152, 175, 54, 80, 25, 151, 115, 197, 147, 145, 41, 196, 149, 208, 10, 60, 2, 234, 190, 225, 120, 197, 51, 91, 60, 218, 17, 246, 191, 154, 102, 143, 205, 171, 131, 177, 231, 199, 235, 199, 160, 92, 248, 56, 137, 158, 133, 198, 214, 235, 204, 163, 142, 84, 199, 94, 75, 205, 136, 28, 178, 57, 46, 136, 48, 186, 155, 194, 170, 167, 188, 13, 236, 186, 129, 112, 126, 71, 88, 183, 244, 70, 209, 211, 1, 172, 174, 88, 3, 255, 155, 118, 209, 108, 160, 95, 225, 132, 8, 67, 175, 9, 171};
#endif
#ifdef VERSION_3
#define CIPHER_LENGTH 147
const uint8_t PAD_KEY[CIPHER_LENGTH] = {17, 204, 71, 184, 196, 17, 234, 194, 19, 237, 45, 42, 86, 112, 48, 187, 7, 98, 98, 184, 205, 45, 96, 177, 39, 175, 78, 26, 177, 146, 56, 168, 91, 253, 142, 225, 93, 181, 149, 186, 67, 231, 252, 19, 181, 137, 6, 7, 157, 193, 132, 178, 137, 145, 130, 207, 42, 194, 255, 161, 239, 160, 109, 128, 33, 93, 62, 76, 86, 108, 7, 99, 58, 155, 247, 25, 55, 164, 48, 254, 181, 247, 196, 233, 184, 222, 3, 116, 171, 124, 115, 97, 41, 214, 56, 67, 110, 165, 214, 188, 172, 190, 200, 188, 107, 191, 249, 78, 154, 94, 162, 231, 70, 84, 66, 207, 21, 213, 116, 25, 221, 161, 127, 116, 183, 252, 62, 31, 72, 180, 230, 228, 148, 98, 211, 191, 97, 212, 107, 125, 219, 254, 79, 225, 33, 122, 27};
const uint8_t CIPHER_TEXT[CIPHER_LENGTH] = {89, 169, 53, 221, 227, 98, 202, 182, 123, 136, 13, 65, 51, 9, 30, 155, 87, 14, 7, 217, 190, 72, 64, 195, 66, 194, 39, 116, 213, 178, 117, 218, 117, 221, 205, 167, 18, 149, 225, 210, 34, 147, 220, 123, 208, 169, 110, 102, 238, 225, 247, 221, 228, 244, 246, 167, 67, 172, 152, 129, 128, 198, 77, 239, 84, 47, 77, 96, 118, 13, 105, 7, 26, 239, 159, 120, 67, 132, 68, 150, 220, 132, 228, 158, 209, 178, 111, 84, 201, 25, 83, 9, 64, 165, 24, 47, 15, 214, 162, 156, 220, 209, 164, 213, 31, 218, 217, 60, 255, 51, 203, 137, 34, 49, 48, 225, 53, 165, 23, 108, 173, 226, 43, 50, 204, 143, 74, 122, 41, 216, 143, 138, 243, 61, 186, 204, 62, 161, 5, 21, 190, 159, 35, 149, 73, 3, 102};
#endif

time_t GLOBAL_START_TIME;
BOOL is_debugger_present;
uint64_t fibonacci_red_herring_a = 0;
uint64_t fibonacci_red_herring_b = 1;

void stage_1();
void stage_1_dead_end_1(int);
void stage_2();
void stage_2_dead_end_1();
void stage_2_dead_end_2(char *);
void stage_2_dead_end_3();
void stage_3();
void stage_3_dead_end_1();
void stage_4();

void stage_1() {
    is_debugger_present = IsDebuggerPresent();
    stage_1_dead_end_1(is_debugger_present);
    if (is_debugger_present == 0) stage_2();
}

void stage_1_dead_end_1(int exit_code) {
    puts("Beware dead ends!");
    Sleep(3000);
    exit(exit_code);
}

void stage_2() {
    time_t current_time = time(NULL);
    if (current_time > GLOBAL_START_TIME + MAX_ELAPSED) {
        if (is_debugger_present == 1) {
            stage_2_dead_end_1();
        } else {
            stage_2_dead_end_2(NULL);
        }
    } else {
        stage_3();
    }
}

void stage_2_dead_end_1() {
    uint8_t buf[GENERIC_BUFFER_MAX] = {166, 144, 138, 223, 158, 141, 154, 145, 216, 139, 223, 155, 144, 145, 154, 223, 134, 154, 139, 209};
    uint8_t * heap_buf = calloc(GENERIC_BUFFER_MAX, sizeof(uint8_t));
    memcpy(heap_buf, buf, GENERIC_BUFFER_MAX);
    uint8_t * counting_pointer = heap_buf;
    for (; *counting_pointer != 0; ++counting_pointer) {
        *counting_pointer = (uint8_t)255 - *counting_pointer;
    }
    puts((char *) heap_buf);
}

void stage_2_dead_end_2(char * buf) {
    if (buf != NULL) {
        puts(buf);
    }
    stage_2_dead_end_3();
}

void stage_2_dead_end_3() {
    char buf[GENERIC_BUFFER_MAX];
    memset(buf, 0, GENERIC_BUFFER_MAX);
    gets_s(buf, GENERIC_BUFFER_MAX);
    stage_2_dead_end_2((char *) &buf);
}

void stage_3() {
    goto trickery;
    stage_4();
    trickery:
    stage_3_dead_end_1();
}

void stage_3_dead_end_1() {
    uint64_t fib_c = fibonacci_red_herring_a + fibonacci_red_herring_b;
    fibonacci_red_herring_a = fibonacci_red_herring_b;
    fibonacci_red_herring_b = fib_c;
    stage_3_dead_end_1();
}

void stage_4() {
    uint8_t buf[CIPHER_LENGTH + 1];
    for (int i = 0; i < CIPHER_LENGTH; ++i) {
        buf[i] = PAD_KEY[i] ^ CIPHER_TEXT[i];
    }
    buf[CIPHER_LENGTH] = 0;
    puts((char *) &buf);
}


int main(int argc, char* argv[]) {
    time(&GLOBAL_START_TIME);

    stage_1();

    return 0;
}
