#include "userprog/syscall.h"
#include <syscall-nr.h>
#include <lib/kernel/stdio.h>
#include <lib/stdio.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

struct file_descriptor {
    tid_t pid;
    struct file *file;
    int fd;
    struct list_elem list_elem;
};

static void syscall_handler(struct intr_frame *);

/* System call functions */
static void sys_halt(void);

static void sys_exit(int);

static tid_t sys_exec(const char *);

static int sys_wait(tid_t);

static bool sys_create(const char *, unsigned);

static bool sys_remove(const char *);

static int sys_open(const char *);

static int sys_filesize(int);

static int sys_read(int, void *, unsigned);

static int sys_write(int, const void *, unsigned);

static void sys_seek(int, unsigned);

static unsigned sys_tell(int);

static void sys_close(int);

/* End of system call functions */

static struct file_descriptor *get_open_file(int);

static void close_open_file(int);

static bool is_valid_uvaddr(const void *);

static uint32_t *esp;

struct list opened_files_list;

static int next_available_fd = 2;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_system_lock);
    list_init(&opened_files_list);
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    esp = f->esp;

    if (!is_valid_ptr(esp) || !is_valid_ptr(esp + 1) ||
        !is_valid_ptr(esp + 2) || !is_valid_ptr(esp + 3)) {
        sys_exit(-1);
        return;
    }

    int sys_call_number = *esp;

    switch (sys_call_number) {
        case SYS_HALT:
            sys_halt();
            break;
        case SYS_EXIT:
            sys_exit(*(esp + 1));
            break;
        case SYS_EXEC:
            f->eax = sys_exec((char *) *(esp + 1));
            break;
        case SYS_WAIT:
            f->eax = sys_wait(*(esp + 1));
            break;
        case SYS_CREATE:
            f->eax = sys_create((char *) *(esp + 1), *(esp + 2));
            break;
        case SYS_REMOVE:
            f->eax = sys_remove((char *) *(esp + 1));
            break;
        case SYS_OPEN:
            f->eax = sys_open((char *) *(esp + 1));
            break;
        case SYS_FILESIZE:
            f->eax = sys_filesize(*(esp + 1));
            break;
        case SYS_READ:
            f->eax = sys_read(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
            break;
        case SYS_WRITE:
            f->eax = sys_write(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
            break;
        case SYS_SEEK:
            sys_seek(*(esp + 1), *(esp + 2));
            break;
        case SYS_TELL:
            f->eax = sys_tell(*(esp + 1));
            break;
        case SYS_CLOSE:
            sys_close(*(esp + 1));
            break;
            /*case SYS_MMAP:
                f->eax = mmap (*(esp + 1), (void *) *(esp + 2));
                break;
            case SYS_MUNMAP:
                munmap (*(esp + 1));
                break;*/
        default:
            break;
    }

}


void sys_halt(void) {

}

static void sys_exit(int status) {
    struct thread *current_thread = thread_current();

    printf("%s: exit(%d)\n", current_thread->name, status);

    thread_exit();
}

static tid_t sys_exec(const char *cmd_line) {

    /* check if the user pinter is valid */
    if (!is_valid_ptr(cmd_line)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    return process_execute(cmd_line);
}

static int sys_wait(tid_t pid) {
    return process_wait(pid);
}

static bool sys_create(const char *file_name, unsigned initial_size) {

    bool status;

    if (!is_valid_ptr(file_name)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    return false;
}

static bool sys_remove(const char *file_name) {
    if (!is_valid_ptr(file_name)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    return false;
}

static int sys_open(const char *file_name) {
    if (!is_valid_ptr(file_name)) {
        sys_exit(-1);
        NOT_REACHED();
    }
    return -1;
}

static int sys_filesize(int fd) {
    return -1;
}

static int sys_read(int fd, void *buffer, unsigned length) {
    if (!is_valid_ptr(buffer) || !is_valid_ptr(buffer + length - 1)) {
        sys_exit(-1);
        NOT_REACHED();
    }
    return -1;
}

static int sys_write(int fd, const void *buffer, unsigned length) {


    if (!is_valid_ptr(buffer) || !is_valid_ptr(buffer + length - 1)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    int bytes_wrote = 0;

    if (fd == STDIN_FILENO) {
        //TODO:Check if it requires 0
        bytes_wrote = -1;
    } else if (fd == STDOUT_FILENO) {
        //TODO:Check
        putbuf(buffer, length);
        bytes_wrote = length;
    }
    return -1;
}

static void sys_seek(int fd, unsigned position) {

}

static unsigned sys_tell(int fd) {
    return 0;
}

static void sys_close(int fd) {

}

bool is_valid_ptr(const void *usr_ptr) {
    struct thread *cur = thread_current();
    if (is_valid_uvaddr(usr_ptr)) {
        return (pagedir_get_page(cur->pagedir, usr_ptr)) != NULL;
    }
    return false;
}


static bool
is_valid_uvaddr(const void *uvaddr) {
    return (uvaddr != NULL && is_user_vaddr(uvaddr));
}