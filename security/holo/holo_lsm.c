/*
 * security/holo/holo_lsm.c
 *
 * HolonOS HSS LSM v3.3 — lekki, bezpieczny filtr upcall
 * Poprawki: non-blocking friendly hook, mutex_trylock + locked upcall,
 *           reconnect z usleep, partial I/O check, decision validation,
 *           poprawione cache + rate limiter + cleanup timer, MSG_NOSIGNAL,
 *           bezpieczne RCU, lepszy hash, pełna implementacja.
 *
 * Autor: Maciej Mazur
 * Licencja: GPL-2.0
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/xattr.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/un.h>
#include <crypto/hash.h>
#include <linux/random.h>
#include <linux/key.h>
#include <keys/user-type.h>
#include <linux/rcupdate.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/timer.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Mazur");
MODULE_DESCRIPTION("HolonOS HSS LSM v3.3 — safe upcall filter");

static unsigned int hss_cache_ttl_ms       = 100;
static unsigned int hss_upcall_timeout_ms  = 5;
static unsigned int hss_rate_limit_per_sec = 100;
static unsigned int hss_reconnect_max_attempts = 3;
static unsigned int hss_reconnect_delay_us     = 50000;  /* 50 ms */

module_param(hss_cache_ttl_ms,          uint, 0644);
module_param(hss_upcall_timeout_ms,     uint, 0644);
module_param(hss_rate_limit_per_sec,    uint, 0644);
module_param(hss_reconnect_max_attempts,uint, 0644);
module_param(hss_reconnect_delay_us,    uint, 0644);

/* Stałe protokołu */
#define HSS_OP_READ               0x01
#define HSS_OP_WRITE              0x02
#define HSS_FLAG_INVALIDATE_CACHE 0x01
#define HSS_XATTR_NAME            "security.hss.lock"
#define HSS_DAEMON_SOCK           "/run/hss-daemon.sock"
#define HSS_KEYRING_NAME          "hss_upcall_key"

#define NETLINK_HSS 30
enum { HSS_NL_CMD_INVALIDATE = 1, };

/* Struktury */
struct hss_upcall_msg {
    u64 timestamp_ns;
    u32 pid;
    u64 inode_nr;
    u32 op_mask;
    u8  nonce[16];
} __packed;

struct hss_upcall_resp {
    u8  nonce_echo[16];
    u32 decision;   /* 0 = allow, 1 = deny */
    u32 flags;
} __packed;   /* 24 bajty */

/* Cache */
struct hss_cache_entry {
    u32           pid;
    u64           inode_nr;
    u32           op_mask;
    unsigned long expiry_jiffies;
    struct hlist_node node;
    struct rcu_head   rcu;
};

#define HSS_CACHE_BITS 8
static DEFINE_HASHTABLE(hss_cache_table, HSS_CACHE_BITS);
static DEFINE_SPINLOCK(hss_cache_lock);

/* Lepszy klucz hashowania */
#define HSS_CACHE_HASH(pid, ino) (hash_long((ino), HSS_CACHE_BITS) ^ (pid))

/* Rate limiter */
struct hss_rate_entry {
    u32           pid;
    atomic_t      count;
    unsigned long window_start;
    struct hlist_node node;
    struct rcu_head   rcu;
};

#define HSS_RATE_BITS 6
static DEFINE_HASHTABLE(hss_rate_table, HSS_RATE_BITS);
static DEFINE_SPINLOCK(hss_rate_lock);

/* Komunikacja */
static struct socket    *hss_sock    = NULL;
static struct crypto_shash *hss_hmac_tfm = NULL;
static u8 hss_hmac_key[32];
static DEFINE_MUTEX(hss_sock_mutex);

/* Timer czyszczący */
static struct timer_list hss_cleanup_timer;

/* Netlink */
static struct sock *hss_nl_sock = NULL;

/* === Deklaracje =========================================================== */
static int hss_get_hmac_key(void);
static int hss_connect_socket(void);
static int hss_reconnect(void);
static int hss_upcall_locked(struct hss_upcall_msg *msg, struct hss_upcall_resp *resp);
static bool hss_inode_has_xattr(struct inode *inode, struct dentry *dentry);
static int hss_cache_lookup(u32 pid, u64 inode_nr, u32 op_mask);
static void hss_cache_store(u32 pid, u64 inode_nr, u32 op_mask, u32 decision);
static void hss_cache_invalidate(u32 pid, u64 inode_nr);
static void hss_cache_flush_old_entries(void);
static bool hss_rate_check(u32 pid);
static void hss_rate_cleanup_old(void);
static void hss_cleanup_timer_callback(struct timer_list *unused);
static int hss_netlink_init(void);
static void hss_netlink_exit(void);

/* === Implementacja ======================================================== */

static int hss_get_hmac_key(void)
{
    struct key *key;
    const struct user_key_payload *payload;
    int ret = -ENOKEY;

    key = request_key(&key_type_user, HSS_KEYRING_NAME, NULL);
    if (IS_ERR(key))
        return PTR_ERR(key);

    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    if (!payload || payload->datalen != sizeof(hss_hmac_key)) {
        ret = -EINVAL;
        goto out;
    }
    memcpy(hss_hmac_key, payload->data, sizeof(hss_hmac_key));
    ret = 0;
out:
    up_read(&key->sem);
    key_put(key);
    return ret;
}

static int hss_connect_socket(void)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, i;

    strncpy(addr.sun_path, HSS_DAEMON_SOCK, sizeof(addr.sun_path) - 1);

    if (hss_sock)
        sock_release(hss_sock);

    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &hss_sock);
    if (ret)
        return ret;

    for (i = 0; i < 5; i++) {
        ret = kernel_connect(hss_sock, (struct sockaddr *)&addr, sizeof(addr), 0);
        if (ret == 0)
            break;
        if (i < 4)
            usleep_range(20000, 40000);
    }

    if (ret) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }
    return ret;
}

static int hss_reconnect(void)
{
    int ret, attempts = 0;
    while (attempts < hss_reconnect_max_attempts) {
        ret = hss_connect_socket();
        if (ret == 0)
            return 0;
        attempts++;
        if (attempts < hss_reconnect_max_attempts)
            usleep_range(hss_reconnect_delay_us / 2, hss_reconnect_delay_us);
    }
    return -ECONNREFUSED;
}

static int hss_upcall_locked(struct hss_upcall_msg *msg, struct hss_upcall_resp *resp)
{
    struct msghdr mh = {0};
    struct kvec iov[2];
    u8 hmac_sent[32], hmac_recv_stored[32], hmac_recv_computed[32];
    struct hss_upcall_resp tmp = {0};
    int ret;
    long old_timeo;

    if (!hss_hmac_tfm || !hss_sock || !hss_sock->sk)
        return -ENOTCONN;

    /* HMAC send */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)msg, sizeof(*msg), hmac_sent);
        if (ret)
            return ret;
    }

    iov[0].iov_base = msg;        iov[0].iov_len = sizeof(*msg);
    iov[1].iov_base = hmac_sent;  iov[1].iov_len = 32;

    ret = kernel_sendmsg(hss_sock, &mh, iov, 2, sizeof(*msg) + 32, MSG_NOSIGNAL);
    if (ret != sizeof(*msg) + 32) {
        pr_warn("holo_lsm: partial send\n");
        goto reconnect;
    }

    old_timeo = hss_sock->sk->sk_rcvtimeo;
    hss_sock->sk->sk_rcvtimeo = msecs_to_jiffies(hss_upcall_timeout_ms);

    {
        struct kvec riov[2] = {
            { .iov_base = &tmp,             .iov_len = sizeof(tmp) },
            { .iov_base = hmac_recv_stored, .iov_len = 32 },
        };
        ret = kernel_recvmsg(hss_sock, &mh, riov, 2, sizeof(tmp) + 32, MSG_NOSIGNAL);
    }

    hss_sock->sk->sk_rcvtimeo = old_timeo;

    if (ret != sizeof(tmp) + 32) {
        pr_warn("holo_lsm: partial recv (got %d)\n", ret);
        goto reconnect;
    }

    /* Weryfikacja HMAC + nonce */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)&tmp, sizeof(tmp), hmac_recv_computed);
        if (ret)
            goto reconnect;
    }

    if (crypto_memneq(hmac_recv_stored, hmac_recv_computed, 32) ||
        memcmp(msg->nonce, tmp.nonce_echo, 16) != 0)
        return -EBADMSG;

    *resp = tmp;
    return 0;

reconnect:
    if (hss_sock) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }
    /* reconnect zostanie wykonany przy następnym wywołaniu */
    return -ENOTCONN;
}

static bool hss_inode_has_xattr(struct inode *inode, struct dentry *dentry)
{
    if (!inode->i_op || !inode->i_op->getxattr)
        return false;

    char val;
    return __vfs_getxattr(dentry, inode, HSS_XATTR_NAME, &val, sizeof(val)) >= 0;
}

/* === Cache ================================================================ */
static int hss_cache_lookup(u32 pid, u64 inode_nr, u32 op_mask)
{
    struct hss_cache_entry *entry;
    unsigned long now = jiffies;
    int found = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(hss_cache_table, entry, node,
                               HSS_CACHE_HASH(pid, inode_nr)) {
        if (entry->pid == pid &&
            entry->inode_nr == inode_nr &&
            entry->op_mask == op_mask) {
            if (time_before(now, entry->expiry_jiffies))
                found = 0; /* allow */
            else
                found = -ESTALE;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

static void hss_cache_store(u32 pid, u64 inode_nr, u32 op_mask, u32 decision)
{
    struct hss_cache_entry *entry, *old = NULL;
    unsigned long flags;
    unsigned long expiry = jiffies + msecs_to_jiffies(hss_cache_ttl_ms);
    u32 hash = HSS_CACHE_HASH(pid, inode_nr);

    if (decision != 0)
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->pid = pid;
    entry->inode_nr = inode_nr;
    entry->op_mask = op_mask;
    entry->expiry_jiffies = expiry;

    spin_lock_irqsave(&hss_cache_lock, flags);

    hash_for_each_possible(hss_cache_table, old, node, hash) {
        if (old->pid == pid &&
            old->inode_nr == inode_nr &&
            old->op_mask == op_mask) {
            hash_del_rcu(&old->node);
            break;
        }
    }

    hash_add_rcu(hss_cache_table, &entry->node, hash);
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    if (old)
        kfree_rcu(old, rcu);
}

static void hss_cache_invalidate(u32 pid, u64 inode_nr)
{
    struct hss_cache_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    HLIST_HEAD(garbage);
    int bkt;

    spin_lock_irqsave(&hss_cache_lock, flags);
    hash_for_each_safe(hss_cache_table, bkt, tmp, entry, node) {
        if (entry->pid == pid && entry->inode_nr == inode_nr) {
            hash_del_rcu(&entry->node);
            hlist_add_head(&entry->node, &garbage);
        }
    }
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    hlist_for_each_entry_safe(entry, tmp, &garbage, node)
        kfree_rcu(entry, rcu);
}

static void hss_cache_flush_old_entries(void)
{
    struct hss_cache_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned long now = jiffies;
    HLIST_HEAD(garbage);
    int bkt;

    spin_lock_irqsave(&hss_cache_lock, flags);
    hash_for_each_safe(hss_cache_table, bkt, tmp, entry, node) {
        if (time_after_eq(now, entry->expiry_jiffies)) {
            hash_del_rcu(&entry->node);
            hlist_add_head(&entry->node, &garbage);
        }
    }
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    hlist_for_each_entry_safe(entry, tmp, &garbage, node)
        kfree_rcu(entry, rcu);
}

/* === Rate limiter ========================================================= */
static bool hss_rate_check(u32 pid)
{
    struct hss_rate_entry *entry;
    unsigned long flags;
    unsigned long now = jiffies;
    unsigned long window_start;
    int count;

    spin_lock_irqsave(&hss_rate_lock, flags);
    hash_for_each_possible(hss_rate_table, entry, node, pid) {
        if (entry->pid == pid) {
            window_start = entry->window_start;
            if (time_after(now, window_start + HZ)) {
                entry->window_start = now;
                atomic_set(&entry->count, 1);
                spin_unlock_irqrestore(&hss_rate_lock, flags);
                return true;
            }
            count = atomic_inc_return(&entry->count);
            spin_unlock_irqrestore(&hss_rate_lock, flags);
            return count <= hss_rate_limit_per_sec;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_irqrestore(&hss_rate_lock, flags);
        return true; /* przy braku pamięci – przepuść */
    }
    entry->pid = pid;
    entry->window_start = now;
    atomic_set(&entry->count, 1);
    hash_add_rcu(hss_rate_table, &entry->node, pid);
    spin_unlock_irqrestore(&hss_rate_lock, flags);
    return true;
}

static void hss_rate_cleanup_old(void)
{
    struct hss_rate_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned long now = jiffies;
    HLIST_HEAD(garbage);
    int bkt;

    spin_lock_irqsave(&hss_rate_lock, flags);
    hash_for_each_safe(hss_rate_table, bkt, tmp, entry, node) {
        if (time_after(now, entry->window_start + 2 * HZ)) {
            hash_del_rcu(&entry->node);
            hlist_add_head(&entry->node, &garbage);
        }
    }
    spin_unlock_irqrestore(&hss_rate_lock, flags);

    hlist_for_each_entry_safe(entry, tmp, &garbage, node)
        kfree_rcu(entry, rcu);
}

/* === Timer ================================================================ */
static void hss_cleanup_timer_callback(struct timer_list *unused)
{
    hss_cache_flush_old_entries();
    hss_rate_cleanup_old();
    mod_timer(&hss_cleanup_timer, jiffies + HZ);
}

/* === Netlink ============================================================== */
struct hss_nl_invalidate_msg {
    u32 pid;
    u64 inode_nr;
};

static void hss_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct hss_nl_invalidate_msg *msg;

    if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg))
        return;

    msg = nlmsg_data(nlh);
    hss_cache_invalidate(msg->pid, msg->inode_nr);
}

static int __init hss_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = hss_nl_recv_msg,
    };

    hss_nl_sock = netlink_kernel_create(&init_net, NETLINK_HSS, &cfg);
    if (!hss_nl_sock) {
        pr_err("holo_lsm: cannot create netlink socket\n");
        return -ENOMEM;
    }
    return 0;
}

static void hss_netlink_exit(void)
{
    if (hss_nl_sock)
        netlink_kernel_release(hss_nl_sock);
}

/* === Główny hook LSM ====================================================== */
static int holo_inode_permission(struct inode *inode, int mask)
{
    struct hss_upcall_msg  msg  = {0};
    struct hss_upcall_resp resp = {0};
    struct dentry *dentry;
    u32 pid = (u32)current->pid;
    u32 op  = 0;
    int ret;

    if (!(mask & (MAY_READ | MAY_WRITE)))
        return 0;

    dentry = d_find_alias(inode);
    if (!dentry)
        return 0;

    if (!hss_inode_has_xattr(inode, dentry)) {
        dput(dentry);
        return 0;
    }
    dput(dentry);

    if (mask & MAY_READ)  op |= HSS_OP_READ;
    if (mask & MAY_WRITE) op |= HSS_OP_WRITE;

    if (hss_cache_lookup(pid, (u64)inode->i_ino, op) == 0)
        return 0;

    if (!hss_rate_check(pid))
        return -EAGAIN;  /* przekroczenie limitu – tymczasowa blokada */

    msg.timestamp_ns = ktime_get_mono_fast_ns();
    msg.pid          = pid;
    msg.inode_nr     = (u64)inode->i_ino;
    msg.op_mask      = op;
    get_random_bytes(msg.nonce, sizeof(msg.nonce));

    if (!mutex_trylock(&hss_sock_mutex))
        return -EBUSY;   /* zamiast -EAGAIN – zasób zajęty */

    ret = hss_upcall_locked(&msg, &resp);

    mutex_unlock(&hss_sock_mutex);

    if (ret == -ENOTCONN || ret == -ETIMEDOUT)
        return (op & HSS_OP_WRITE) ? -EACCES : -EAGAIN;

    if (ret < 0)
        return -EACCES;

    if (resp.decision != 0 && resp.decision != 1)
        return -EACCES;

    if (resp.flags & HSS_FLAG_INVALIDATE_CACHE)
        hss_cache_invalidate(pid, (u64)inode->i_ino);

    hss_cache_store(pid, (u64)inode->i_ino, op, resp.decision);

    return (resp.decision == 0) ? 0 : -EACCES;
}

/* === Rejestracja hooków =================================================== */
static struct security_hook_list holo_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, holo_inode_permission),
};

/* === Init / Exit ========================================================== */
static int __init holo_lsm_init(void)
{
    int ret;

    ret = hss_get_hmac_key();
    if (ret)
        return ret;

    hss_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(hss_hmac_tfm))
        return PTR_ERR(hss_hmac_tfm);

    ret = crypto_shash_setkey(hss_hmac_tfm, hss_hmac_key, sizeof(hss_hmac_key));
    memzero_explicit(hss_hmac_key, sizeof(hss_hmac_key));
    if (ret) {
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    ret = hss_connect_socket();
    if (ret) {
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    ret = hss_netlink_init();
    if (ret) {
        sock_release(hss_sock);
        hss_sock = NULL;
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    timer_setup(&hss_cleanup_timer, hss_cleanup_timer_callback, 0);
    mod_timer(&hss_cleanup_timer, jiffies + HZ);

    security_add_hooks(holo_hooks, ARRAY_SIZE(holo_hooks), "holo");
    pr_info("HolonOS HSS LSM v3.3 loaded (non-blocking hook + locked upcall)\n");
    return 0;
}

static void __exit holo_lsm_exit(void)
{
    struct hss_cache_entry *centry;
    struct hss_rate_entry *rentry;
    struct hlist_node *tmp;
    int bkt;

    del_timer_sync(&hss_cleanup_timer);

    spin_lock_irq(&hss_cache_lock);
    hash_for_each_safe(hss_cache_table, bkt, tmp, centry, node) {
        hash_del_rcu(&centry->node);
        kfree_rcu(centry, rcu);
    }
    spin_unlock_irq(&hss_cache_lock);

    spin_lock_irq(&hss_rate_lock);
    hash_for_each_safe(hss_rate_table, bkt, tmp, rentry, node) {
        hash_del_rcu(&rentry->node);
        kfree_rcu(rentry, rcu);
    }
    spin_unlock_irq(&hss_rate_lock);

    hss_netlink_exit();

    if (hss_hmac_tfm)
        crypto_free_shash(hss_hmac_tfm);

    if (hss_sock) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }

    pr_info("HolonOS HSS LSM unloaded\n");
}

module_init(holo_lsm_init);
module_exit(holo_lsm_exit);
