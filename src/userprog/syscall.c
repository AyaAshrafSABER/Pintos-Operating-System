#include "userprog/syscall.h"
#include <stdio.h>
#include <src/lib/syscall-nr.h>
#include "threads/interrupt.h"

static void syscall_handler(struct intr_frame *);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {
    printf("system call!\n");

    int sys_call_number; //TODO:Fetch the sys_call_number enum

    switch (sys_call_number) {
        case SYS_HALT:                   /* Halt the operating system. */
            halt();
            break;
        case SYS_EXIT:                 /* Terminate this process. */
            exit(arg0);
            break;
        case SYS_EXEC:                 /* Start another process. */
            exec(arg0);
            break;
        case SYS_WAIT:                 /* Wait for a child process to die. */
            wait(arg0);
            break;
        case SYS_CREATE:                 /* Create a file. */
            create(arg0, arg1);
            break;
        case SYS_REMOVE:                 /* Delete a file. */
            remove(arg0);
            break;
        case SYS_OPEN:                 /* Open a file. */
            open(arg0);
            break;
        case SYS_FILESIZE:               /* Obtain a file's size. */
            filesize(arg0);
            break;
        case SYS_READ:                   /* Read from a file. */
            read(arg0, arg1, arg2);
            break;
        case SYS_WRITE:                  /* Write to a file. */
            write(arg0, arg1, arg2);
            break;
        case SYS_SEEK:                   /* Change position in a file. */
            seek(arg0, arg1);
            break;
        case SYS_TELL:                  /* Report current position in a file. */
            tell(arg0);
            break;
        case SYS_CLOSE:
            close(arg0);
            break;
    }

}

void halt(void) {

}

void exit(int status) {

}

pid_t exec(const char *file) {
    return 0;
}

int wait(pid_t pid) {
    return 0;
}

bool create(const char *file, unsigned initial_size) {
    return false;
}

bool remove(const char *file) {
    return false;
}

int open(const char *file) {
    return 0;
}

int filesize(int fd) {
    return 0;
}

int read(int fd, void *buffer, unsigned length) {
    return 0;
}

int write(int fd, const void *buffer, unsigned length) {
    return 0;
}

void seek(int fd, unsigned position) {

}

unsigned tell(int fd) {
    return 0;
}

void close(int fd) {

}