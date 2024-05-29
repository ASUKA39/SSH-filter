#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME "ssh_filter"
#define CLASS_NAME "ssh"

static struct nf_hook_ops ssh_filter_hook;
static struct class* ssh_filter_class = NULL;
static struct device* ssh_filter_device = NULL;
static char message[256] = {0};
static short size_of_message;
static int number_opens = 0;
static struct list_head whitelist;
static struct list_head blacklist;
static int major_number;

static bool use_whitelist = false;  // false: 使用黑名单模式，true: 使用白名单模式

struct ip_list {
    struct list_head list;
    uint32_t ip;
};

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
};

unsigned int ssh_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct ip_list *entry;
    char source_ip[16];
    if (!skb) {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        snprintf(source_ip, 16, "%pI4", &ip_header->saddr);

        if(ntohs(tcp_header->dest) == 22) {     // SSH
            if (!use_whitelist) {
                list_for_each_entry(entry, &blacklist, list) {  // 遍历黑名单
                    if (entry->ip == ip_header->saddr) {
                        printk(KERN_INFO "SSH connection from %s blocked (blacklist)\n", source_ip);
                        return NF_DROP;
                    }
                }
                printk(KERN_INFO "SSH connection from %s allowed (not in blacklist)\n", source_ip);
                return NF_ACCEPT;
            } else {
                list_for_each_entry(entry, &whitelist, list) {  // 遍历白名单
                    if (entry->ip == ip_header->saddr) {
                        printk(KERN_INFO "SSH connection from %s allowed (whitelist)\n", source_ip);
                        return NF_ACCEPT;
                    }
                }
                printk(KERN_INFO "SSH connection from %s blocked (not in whitelist)\n", source_ip);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static int __init ssh_filter_init(void) {
    INIT_LIST_HEAD(&whitelist);
    INIT_LIST_HEAD(&blacklist);

    ssh_filter_hook.hook = ssh_filter;
    ssh_filter_hook.hooknum = NF_INET_LOCAL_IN;
    ssh_filter_hook.pf = PF_INET;
    ssh_filter_hook.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &ssh_filter_hook);  // 注册 netfilter hook

    major_number = register_chrdev(0, DEVICE_NAME, &fops);  // 注册字符设备驱动，用于用户设置白名单/黑名单
    if (major_number < 0) {
        printk(KERN_ALERT "SSH filter failed to register a major number\n");
        return major_number;
    }

    ssh_filter_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(ssh_filter_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(ssh_filter_class);
    }

    ssh_filter_device = device_create(ssh_filter_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(ssh_filter_device)) {
        class_destroy(ssh_filter_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(ssh_filter_device);
    }

    printk(KERN_INFO "SSH filter module loaded\n");
    return 0;
}

static void __exit ssh_filter_exit(void) {
    struct ip_list *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &whitelist, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    list_for_each_entry_safe(entry, tmp, &blacklist, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    nf_unregister_net_hook(&init_net, &ssh_filter_hook);

    device_destroy(ssh_filter_class, MKDEV(major_number, 0));
    class_unregister(ssh_filter_class);
    class_destroy(ssh_filter_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    printk(KERN_INFO "SSH filter module unloaded\n");
}

static int device_open(struct inode *inodep, struct file *filep) {
    number_opens++;
    printk(KERN_INFO "SSH filter device opened %d time(s)\n", number_opens);
    return 0;
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    struct ip_list *entry;
    char temp_buffer[1024] = {0};
    char ip_str[16];
    size_t length = 0;

    length += snprintf(temp_buffer + length, sizeof(temp_buffer) - length, "Current mode: %s\n", use_whitelist ? "Whitelist" : "Blacklist");

    length += snprintf(temp_buffer + length, sizeof(temp_buffer) - length, "Blacklist:\n");
    list_for_each_entry(entry, &blacklist, list) {
        snprintf(ip_str, 16, "%pI4", &entry->ip);
        length += snprintf(temp_buffer + length, sizeof(temp_buffer) - length, "\t%s\n", ip_str);
    }

    length += snprintf(temp_buffer + length, sizeof(temp_buffer) - length, "Whitelist:\n");
    list_for_each_entry(entry, &whitelist, list) {
        snprintf(ip_str, 16, "%pI4", &entry->ip);
        length += snprintf(temp_buffer + length, sizeof(temp_buffer) - length, "\t%s\n", ip_str);
    }

    if (*offset >= length) {
        return 0;
    }

    if (len + *offset > length) {
        len = length - *offset;
    }

    if (copy_to_user(buffer, temp_buffer + *offset, len)) {
        return -EFAULT;
    }

    *offset += len;

    return len;
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    struct ip_list *entry;
    uint32_t ip;
    char cmd;
    char ip_str[17] = {0};

    if (len < 2 || len > 256) return -EINVAL;

    if (copy_from_user(message, buffer, len)) return -EFAULT;
    message[len] = '\0';

    sscanf(message, "%c %s", &cmd, ip_str);
    in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL);

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return -ENOMEM;

    entry->ip = ip;

    if (cmd == 'm') {
        if (ip_str[0] == 'w') {
            use_whitelist = true;
            printk(KERN_INFO "Switched to whitelist mode\n");
        } else if (ip_str[0] == 'b') {
            use_whitelist = false;
            printk(KERN_INFO "Switched to blacklist mode\n");
        } else {
            return -EINVAL;
        }
    } else {
        if (cmd == 'b') {
            unsigned int flag = 0;
            struct ip_list *entry_tmp;
            list_for_each_entry(entry_tmp, &whitelist, list) {
                if (entry_tmp->ip == ip) {
                    list_del(&entry_tmp->list);
                    kfree(entry_tmp);
                    printk(KERN_INFO "Removed %s from whitelist\n", ip_str);
                    flag = 1;
                    break;
                }
            }
            if (flag == 0) {
                unsigned int is_in_blacklist = 0;
                struct ip_list *entry_tmp;
                list_for_each_entry(entry_tmp, &blacklist, list) {
                    if (entry_tmp->ip == ip) {
                        printk(KERN_INFO "IP %s already in blacklist\n", ip_str);
                        is_in_blacklist = 1;
                        break;
                    }
                }
                if (is_in_blacklist == 0) {
                    list_add(&entry->list, &blacklist);
                    printk(KERN_INFO "Added %s to blacklist\n", ip_str);
                }
            }
        } else if (cmd == 'w') {
            unsigned int flag = 0;
            struct ip_list *entry_tmp;
            list_for_each_entry(entry_tmp, &blacklist, list) {
                if (entry_tmp->ip == ip) {
                    list_del(&entry_tmp->list);
                    kfree(entry_tmp);
                    printk(KERN_INFO "Removed %s from blacklist\n", ip_str);
                    flag = 1;
                    break;
                }
            }
            if (flag == 0) {
                unsigned int is_in_whitelist = 0;
                struct ip_list *entry_tmp;
                list_for_each_entry(entry_tmp, &whitelist, list) {
                    if (entry_tmp->ip == ip) {
                        printk(KERN_INFO "IP %s already in whitelist\n", ip_str);
                        is_in_whitelist = 1;
                        break;
                    }
                }
                if (is_in_whitelist == 0) {
                    list_add(&entry->list, &whitelist);
                    printk(KERN_INFO "Added %s to whitelist\n", ip_str);
                }
            }
        } else {
            kfree(entry);
            return -EINVAL;
        }
    }

    size_of_message = strlen(message);
    return len;
}

static int device_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "SSH filter device closed\n");
    return 0;
}

module_init(ssh_filter_init);
module_exit(ssh_filter_exit);
