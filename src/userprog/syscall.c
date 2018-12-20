#include "userprog/syscall.h"
#include <syscall-nr.h>
#include <lib/kernel/stdio.h>
#include <lib/stdio.h>
#include <devices/shutdown.h>
#include <threads/malloc.h>
#include <threads/malloc.h>
#include <devices/input.h>
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

static void close_open_file(int);

static bool is_valid_uvaddr(const void *);

static struct file_descriptor *get_opened_file(int fd);

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
    shutdown_power_off();
}

static void sys_exit(int status) {
    struct thread *current_thread = thread_current();
    struct thread *parent_thread = thread_get_by_id(current_thread->parent_id);

    printf("%s: exit(%d)\n", current_thread->name, status);

    if (parent_thread != NULL) {

        lock_acquire(&parent_thread->lock_child);

        struct list_elem *e = list_tail(&parent_thread->children_status);
        while ((e = list_prev(e)) != list_head(&parent_thread->children_status)) {
            struct child_status *child_status = list_entry (e, struct child_status, list_elem);
            if (child_status->child_pid == current_thread->tid) {
                child_status->is_exit_called = true;
                child_status->exit_status = status;
            }
        }

        if (parent_thread->child_load_status == LOAD_STATUS_LOADING)
            parent_thread->child_load_status = LOAD_STATUS_FAIL;

        cond_signal(&parent_thread->cond_child, &parent_thread->lock_child);

        lock_release(&parent_thread->lock_child);
    }

    thread_exit();
}

static tid_t sys_exec(const char *cmd_line) {

    /* check if the user pinter is valid */
    if (!is_valid_ptr(cmd_line)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    struct thread *cur = thread_current();
    cur->child_load_status = LOAD_STATUS_LOADING;

    tid_t tid = process_execute(cmd_line);
    lock_acquire(&cur->lock_child);

    while (cur->child_load_status == LOAD_STATUS_LOADING)
        cond_wait(&cur->cond_child, &cur->lock_child);

    if (cur->child_load_status == LOAD_STATUS_FAIL)
        tid = TID_ERROR;

    lock_release(&cur->lock_child);

    return tid;
}

static int sys_wait(tid_t pid) {
    return process_wait(pid);
}

static bool sys_create(const char *file_name, unsigned initial_size) {

    bool status;

    if (!is_valid_ptr(file_name))
        sys_exit(-1);

    lock_acquire(&file_system_lock);
    status = filesys_create(file_name, initial_size);
    lock_release(&file_system_lock);

    return status;
    return false;
}

static bool sys_remove(const char *file_name) {
    if (!is_valid_ptr(file_name)) {
        sys_exit(-1);
        NOT_REACHED();
    }

    bool status;

    lock_acquire(&file_system_lock);
    status = filesys_remove(file_name);
    lock_release(&file_system_lock);

    return status;
}

static int sys_open(const char *file_name) {
    if (!is_valid_ptr(file_name)) {
        sys_exit(-1);
        NOT_REACHED();
    }
    int status = -1;
    struct file_descriptor *file_descriptor;

    lock_acquire(&file_system_lock);

    struct file *file = filesys_open(file_name);

    if (file != NULL) {
        file_descriptor = calloc(1, sizeof *file_descriptor);

        file_descriptor->file = file;
        file_descriptor->pid = thread_current()->tid;
        file_descriptor->fd = next_available_fd;

        status = next_available_fd;

        next_available_fd++;

        list_push_back(&opened_files_list, &file_descriptor->list_elem);
    }

    lock_release(&file_system_lock);


    return status;
}

static int sys_filesize(int fd) {


    int size = -1;

    lock_acquire(&file_system_lock);

    struct file_descriptor *file_descriptor = get_opened_file(fd);

    if (file_descriptor != NULL) {
        size = file_length(file_descriptor->file);
    }

    lock_release(&file_system_lock);

    return size;
}

static int sys_read(int fd, void *buffer, unsigned length) {
    if (!is_valid_ptr(buffer) || !is_valid_ptr(buffer + length - 1) || fd < 0) {
        sys_exit(-1);
        NOT_REACHED();
    }

    int bytes_read = 0;

    lock_acquire(&file_system_lock);

    if (fd == STDOUT_FILENO) {

        bytes_read = -1;

    } else if (fd == STDIN_FILENO) {

        //TODO: if it's allowed to move past the allowed file size

        unsigned int counter = length;
        uint8_t character;
        uint8_t *temp_buffer = buffer;

        while (counter > 1 && (character = input_getc()) != 0) {
            *temp_buffer = character;
            buffer++;
            counter--;
        }

        *temp_buffer = 0;

        bytes_read = length - counter;

    } else {
        struct file_descriptor *file_descriptor = get_opened_file(fd);

        if (file_descriptor->file == NULL) {
            //TODO:Check if it requires to return -1
            bytes_read = 0;
        } else {
            bytes_read = file_read(file_descriptor->file, buffer, length);
        }
    }

    lock_release(&file_system_lock);

    return bytes_read;
}

static int sys_write(int fd, const void *buffer, unsigned length) {


    if (!is_valid_ptr(buffer) || !is_valid_ptr(buffer + length - 1) || fd < 0) {
        sys_exit(-1);
        NOT_REACHED();
    }

    int bytes_wrote = 0;

    lock_acquire(&file_system_lock);

    if (fd == STDIN_FILENO) {
        //TODO:Check if it requires 0
        bytes_wrote = -1;
    } else if (fd == STDOUT_FILENO) {
        //TODO:Check
        putbuf(buffer, length);
        bytes_wrote = length;
    } else {
        struct file_descriptor *file_descriptor = get_opened_file(fd);

        if (file_descriptor->file == NULL) {
            //TODO:Check if it requires to return -1
            bytes_wrote = 0;
        } else {
            bytes_wrote = file_write(file_descriptor->file, buffer, length);
        }
    }

    lock_release(&file_system_lock);

    return bytes_wrote;
}

static void sys_seek(int fd, unsigned position) {
    lock_acquire(&file_system_lock);

    struct file_descriptor *file_descriptor = get_opened_file(fd);

    if (file_descriptor != NULL) {
        file_seek(file_descriptor->file, position);
    }

    lock_release(&file_system_lock);
}

static unsigned sys_tell(int fd) {
    //TODO: Check if it requires -1 to return

    int tell_position = 0;

    lock_acquire(&file_system_lock);

    struct file_descriptor *file_descriptor = get_opened_file(fd);

    if (file_descriptor != NULL) {
        tell_position = file_tell(file_descriptor->file);
    }

    lock_release(&file_system_lock);

    return (unsigned int) tell_position;
}

static void sys_close(int fd) {
    lock_acquire(&file_system_lock);

    struct file_descriptor *file_descriptor = get_opened_file(fd);

    if (file_descriptor != NULL && file_descriptor->pid == thread_current()->tid) {
        list_remove(&file_descriptor->list_elem);
        file_close(file_descriptor->file);
        free(file_descriptor);
    }

    lock_release(&file_system_lock);
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

static struct file_descriptor *get_opened_file(int fd) {
    struct list_elem *e;
    struct file_descriptor *fd_struct;
    e = list_tail(&opened_files_list);
    while ((e = list_prev(e)) != list_head(&opened_files_list)) {
        fd_struct = list_entry (e, struct file_descriptor, list_elem);
        if (fd_struct->fd == fd)
            return fd_struct;
    }
    return NULL;
}
void
close_file_by_owner (tid_t tid)
{
    struct list_elem *e;
    struct list_elem *next;
    struct file_descriptor *fd_struct;
    e = list_begin (&opened_files_list);
    while (e != list_tail (&opened_files_list))
    {
        next = list_next (e);
        fd_struct = list_entry (e, struct file_descriptor, list_elem);
        if (fd_struct->pid == tid)
        {
            list_remove (e);
            file_close (fd_struct->file);
            free (fd_struct);
        }
        e = next;
    }
}