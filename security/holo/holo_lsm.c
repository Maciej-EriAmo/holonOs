/*
 * security/holo/holo_lsm.c
 *
 * HolonOS HSS LSM v4.0 – production ready
 *
 * Wymaga architektury 64-bit (LP64/LLP64).
 * Port na 32-bit wymaga dostosowania typów hash i precyzji FP.
 *
 * Zmiany v4.0:
 *   - partial send: iov rebuild zamiast mutacji (poprawność)
 *   - eviction: pełny wrap modulo (równomierna dystrybucja)
 *   - circuit breaker: użyj module_param zamiast hardcode
 *   - xattr: granularna obsługa błędów (-EIO vs -ESTALE)
 *
 * Zmiany v3.9:
 *   - partial send loop (fix reconnect storm)
 *   - eviction fallback (gwarantowane zwolnienie miejsca)
 *   - cache count sanity check (drift protection)
 *   - timeout default 15ms (redukcja false positives)
 *   - xattr fail-closed z logowaniem
 *
 * Zmiany v3.8:
 *   - xattr fail-closed (IO error → deny)
 *   - cache random eviction zamiast hard drop
 *   - circuit breaker decay w timerze
 *
 * Zmiany v3.7:
 *   - MSG_WAITALL w recvmsg (fix partial recv)
 *   - crypto_memneq dla nonce (timing-safe)
 *   - op_mask w cache hash (redukcja kolizji)
 *   - cache size limit 4096 entries (memory cap)
 *
 * Zmiany v3.6:
 *   - single-flight reconnect (atomic flag) eliminuje thundering herd
 *   - rozdzielony cache decyzji (przechowuje zarówno ALLOW, jak i DENY)
 *   - ulepszony klucz rate-limitera: ((u64)pid << 32) | op_mask
 *   - netlink: wymagane CAP_SYS_ADMIN (oprócz UID 0)
 *   - circuit breaker: po N błędach upcall przechodzi w tryb fail-open/closed
 *   - hardening nonce: memset(msg, 0, sizeof(msg))
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
#include <linux/compiler.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Mazur");
MODULE_DESCRIPTION("HolonOS HSS LSM v4.0 – production ready");

static unsigned int hss_cache_ttl_ms       = 100;
static unsigned int hss_cache_deny_ttl_ms  = 1000;
static unsigned int hss_upcall_timeout_ms  = 15;
static unsigned int hss_rate_limit_per_sec = 100;
static unsigned int hss_reconnect_max_attempts = 3;
static unsigned int hss_reconnect_delay_us     = 50000;
static unsigned int hss_circuit_breaker_threshold = 100;

module_param(hss_cache_ttl_ms,          uint, 0644);
module_param(hss_cache_deny_ttl_ms,     uint, 0644);
module_param(hss_upcall_timeout_ms,     uint, 0644);
module_param(hss_rate_limit_per_sec,    uint, 0644);
module_param(hss_reconnect_max_attempts,uint, 0644);
module_param(hss_reconnect_delay_us,    uint, 0644);
module_param(hss_circuit_breaker_threshold, uint, 0644);

/* Stałe protokołu */
#define HSS_OP_READ               0x01
#define HSS_OP_WRITE              0x02
#define HSS_FLAG_INVALIDATE_CACHE 0x01
#define HSS_XATTR_NAME            "security.hss.lock"
#define HSS_DAEMON_SOCK           "/run/hss-daemon.sock"
#define HSS_KEYRING_NAME          "hss_upcall_key"
#define HSS_CACHE_MAX_ENTRIES     4096

#define NETLINK_HSS 30
enum { HSS_NL_CMD_INVALIDATE = 1, };

/* Struktury */
struct hss_upcall_msg {
    u64 timestamp_ns;
    u32 pid;
    u64 inode_id;
    u32 op_mask;
    u8  nonce[16];
} __packed;

struct hss_upcall_resp {
    u8  nonce_echo[16];
    u32 decision;
    u32 flags;
} __packed;

/* Cache */
struct hss_cache_entry {
    u32           pid;
    u64           inode_id;
    u32           op_mask;
    u32           decision;
    unsigned long expiry_jiffies;
    struct hlist_node node;
    struct rcu_head   rcu;
};

#define HSS_CACHE_BITS 8
#define HSS_CACHE_BUCKETS (1 << HSS_CACHE_BITS)
static DEFINE_HASHTABLE(hss_cache_table, HSS_CACHE_BITS);
static DEFINE_SPINLOCK(hss_cache_lock);
static atomic_t hss_cache_count = ATOMIC_INIT(0);

static inline u32 hss_cache_hash(u32 pid, u64 inode_id, u32 op_mask)
{
    u64 key = ((u64)pid << 32) ^ inode_id ^ op_mask;
    return hash_long(key, HSS_CACHE_BITS);
}

/* Rate limiter */
struct hss_rate_entry {
    u32           pid;
    u32           op_mask;
    atomic_t      count;
    unsigned long window_start;
    struct hlist_node node;
    struct rcu_head   rcu;
};

#define HSS_RATE_BITS 6
static DEFINE_HASHTABLE(hss_rate_table, HSS_RATE_BITS);
static DEFINE_SPINLOCK(hss_rate_lock);

static inline u64 hss_rate_key(u32 pid, u32 op_mask)
{
    return ((u64)pid << 32) | op_mask;
}

/* Komunikacja */
static struct socket    *hss_sock    = NULL;
static struct crypto_shash *hss_hmac_tfm = NULL;
static u8 hss_hmac_key[32];
static DEFINE_MUTEX(hss_sock_mutex);
static atomic_t hss_reconnecting = ATOMIC_INIT(0);

/* Circuit breaker */
static atomic_t hss_upcall_fail_count = ATOMIC_INIT(0);

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
static int hss_cache_lookup(u32 pid, u64 inode_id, u32 op_mask);
static void hss_cache_evict_one(void);
static void hss_cache_store(u32 pid, u64 inode_id, u32 op_mask, u32 decision);
static void hss_cache_invalidate(u32 pid, u64 inode_id, u32 op_mask);
static void hss_cache_flush_old_entries(void);
static bool hss_rate_check(u32 pid, u32 op_mask);
static void hss_rate_cleanup_old(void);
static void hss_cleanup_timer_callback(struct timer_list *unused);
static int hss_netlink_init(void);
static void hss_netlink_exit(void);
static void hss_cache_count_sanity_check(void);

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

    mutex_lock(&hss_sock_mutex);

    if (hss_sock) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }

    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &hss_sock);
    if (ret)
        goto out;

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

out:
    mutex_unlock(&hss_sock_mutex);
    return ret;
}

static int hss_reconnect(void)
{
    int ret = -ECONNREFUSED;
    int attempts = 0;

    if (atomic_cmpxchg(&hss_reconnecting, 0, 1) != 0)
        return -EALREADY;

    mutex_lock(&hss_sock_mutex);

    while (attempts < hss_reconnect_max_attempts) {
        mutex_unlock(&hss_sock_mutex);
        ret = hss_connect_socket();
        mutex_lock(&hss_sock_mutex);

        if (ret == 0)
            break;

        attempts++;
        if (attempts < hss_reconnect_max_attempts) {
            mutex_unlock(&hss_sock_mutex);
            usleep_range(hss_reconnect_delay_us / 2, hss_reconnect_delay_us);
            mutex_lock(&hss_sock_mutex);
        }
    }

    mutex_unlock(&hss_sock_mutex);
    atomic_set(&hss_reconnecting, 0);
    return ret ? -ECONNREFUSED : 0;
}

static int hss_upcall_locked(struct hss_upcall_msg *msg, struct hss_upcall_resp *resp)
{
    struct msghdr mh = { .msg_flags = MSG_NOSIGNAL };
    u8 hmac_sent[32], hmac_recv_stored[32], hmac_recv_computed[32];
    struct hss_upcall_resp tmp = {0};
    int ret;
    long old_timeo;
    struct socket *sock = READ_ONCE(hss_sock);
    size_t total_sent = 0;
    size_t msg_len = sizeof(*msg);
    size_t hmac_len = 32;
    size_t expected_send = msg_len + hmac_len;

    if (!hss_hmac_tfm || !sock || !READ_ONCE(sock->sk))
        return -ENOTCONN;

    /* HMAC send */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)msg, sizeof(*msg), hmac_sent);
        if (ret)
            return ret;
    }

    /* Partial send loop z iov rebuild */
    while (total_sent < expected_send) {
        struct kvec iov[2];
        int iov_count = 0;
        size_t offset = total_sent;

        /* Rebuild iov od aktualnego offsetu */
        if (offset < msg_len) {
            iov[iov_count].iov_base = (u8 *)msg + offset;
            iov[iov_count].iov_len = msg_len - offset;
            iov_count++;
            offset = 0;
        } else {
            offset -= msg_len;
        }

        if (iov_count == 0 || total_sent >= msg_len) {
            size_t hmac_offset = (total_sent > msg_len) ? (total_sent - msg_len) : 0;
            if (hmac_offset < hmac_len) {
                iov[iov_count].iov_base = hmac_sent + hmac_offset;
                iov[iov_count].iov_len = hmac_len - hmac_offset;
                iov_count++;
            }
        }

        if (iov_count == 0)
            break;

        ret = kernel_sendmsg(sock, &mh, iov, iov_count, expected_send - total_sent);
        if (ret <= 0) {
            pr_warn("holo_lsm: send failed (ret=%d, sent=%zu/%zu)\n",
                    ret, total_sent, expected_send);
            return -ENOTCONN;
        }
        total_sent += ret;
    }

    old_timeo = sock->sk->sk_rcvtimeo;
    sock->sk->sk_rcvtimeo = msecs_to_jiffies(hss_upcall_timeout_ms);

    {
        struct kvec riov[2] = {
            { .iov_base = &tmp,             .iov_len = sizeof(tmp) },
            { .iov_base = hmac_recv_stored, .iov_len = 32 },
        };
        ret = kernel_recvmsg(sock, &mh, riov, 2, sizeof(tmp) + 32, MSG_WAITALL);
    }

    sock->sk->sk_rcvtimeo = old_timeo;

    if (ret != sizeof(tmp) + 32) {
        pr_warn("holo_lsm: partial recv (got %d)\n", ret);
        return -ENOTCONN;
    }

    /* Weryfikacja HMAC + nonce (timing-safe) */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)&tmp, sizeof(tmp), hmac_recv_computed);
        if (ret)
            return ret;
    }

    if (crypto_memneq(hmac_recv_stored, hmac_recv_computed, 32) ||
        crypto_memneq(msg->nonce, tmp.nonce_echo, 16))
        return -EBADMSG;

    *resp = tmp;
    return 0;
}

static bool hss_inode_has_xattr(struct inode *inode, struct dentry *dentry)
{
    char val;
    int ret;

    if (!inode->i_op || !inode->i_op->getxattr)
        return false;

    ret = __vfs_getxattr(dentry, inode, HSS_XATTR_NAME, &val, sizeof(val));

    if (ret >= 0)
        return true;

    /* Brak xattr lub FS nie wspiera */
    if (ret == -ENODATA || ret == -EOPNOTSUPP || ret == -ENOTSUP)
        return false;

    /* Stale handle - soft fail, nie blokuj */
    if (ret == -ESTALE) {
        pr_debug("holo_lsm: xattr ESTALE, soft fail\n");
        return false;
    }

    /* IO error, permission error - fail-closed */
    if (ret == -EIO || ret == -EACCES || ret == -EPERM) {
        pr_warn_ratelimited("holo_lsm: xattr check failed (err=%d), fail-closed\n", ret);
        return true;
    }

    /* Inne błędy - fail-closed z logiem */
    pr_warn_ratelimited("holo_lsm: xattr unexpected error (err=%d), fail-closed\n", ret);
    return true;
}

/* === Cache count sanity =================================================== */
static void hss_cache_count_sanity_check(void)
{
    int count = atomic_read(&hss_cache_count);
    if (count < 0) {
        pr_warn("holo_lsm: cache count drift detected (%d), resetting\n", count);
        atomic_set(&hss_cache_count, 0);
    }
}

/* === Cache (ALLOW/DENY) ================================================== */
static int hss_cache_lookup(u32 pid, u64 inode_id, u32 op_mask)
{
    struct hss_cache_entry *entry;
    unsigned long now = jiffies;
    int decision = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(hss_cache_table, entry, node,
                               hss_cache_hash(pid, inode_id, op_mask)) {
        if (READ_ONCE(entry->pid) == pid &&
            READ_ONCE(entry->inode_id) == inode_id &&
            READ_ONCE(entry->op_mask) == op_mask) {
            if (time_before(now, READ_ONCE(entry->expiry_jiffies)))
                decision = READ_ONCE(entry->decision);
            else
                decision = -ESTALE;
            break;
        }
    }
    rcu_read_unlock();

    if (decision == 0)
        return 0;
    else if (decision == 1)
        return -EACCES;
    else
        return -ENOENT;
}

static void hss_cache_evict_one(void)
{
    struct hss_cache_entry *victim = NULL;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned long now = jiffies;
    int i, bkt;
    u32 start_bkt;

    get_random_bytes(&start_bkt, sizeof(start_bkt));
    start_bkt %= HSS_CACHE_BUCKETS;

    spin_lock_irqsave(&hss_cache_lock, flags);

    /* Faza 1: szukaj expired entry (pełny wrap) */
    for (i = 0; i < HSS_CACHE_BUCKETS; i++) {
        bkt = (start_bkt + i) % HSS_CACHE_BUCKETS;
        hlist_for_each_entry_safe(victim, tmp, &hss_cache_table[bkt], node) {
            if (time_after_eq(now, victim->expiry_jiffies)) {
                hash_del_rcu(&victim->node);
                atomic_dec(&hss_cache_count);
                spin_unlock_irqrestore(&hss_cache_lock, flags);
                kfree_rcu(victim, rcu);
                return;
            }
        }
    }

    /* Faza 2: brak expired — usuń pierwszy napotkany (pełny wrap) */
    victim = NULL;
    for (i = 0; i < HSS_CACHE_BUCKETS; i++) {
        bkt = (start_bkt + i) % HSS_CACHE_BUCKETS;
        hlist_for_each_entry_safe(victim, tmp, &hss_cache_table[bkt], node) {
            hash_del_rcu(&victim->node);
            atomic_dec(&hss_cache_count);
            spin_unlock_irqrestore(&hss_cache_lock, flags);
            kfree_rcu(victim, rcu);
            return;
        }
    }

    spin_unlock_irqrestore(&hss_cache_lock, flags);
}

static void hss_cache_store(u32 pid, u64 inode_id, u32 op_mask, u32 decision)
{
    struct hss_cache_entry *entry, *old = NULL;
    unsigned long flags;
    unsigned long expiry;
    u32 hash;

    /* Sanity check przed operacją */
    hss_cache_count_sanity_check();

    /* Evict zamiast drop przy pełnym cache */
    if (atomic_read(&hss_cache_count) >= HSS_CACHE_MAX_ENTRIES)
        hss_cache_evict_one();

    expiry = jiffies + msecs_to_jiffies(
        (decision == 0) ? hss_cache_ttl_ms : hss_cache_deny_ttl_ms);
    hash = hss_cache_hash(pid, inode_id, op_mask);

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->pid = pid;
    entry->inode_id = inode_id;
    entry->op_mask = op_mask;
    entry->decision = decision;
    entry->expiry_jiffies = expiry;

    spin_lock_irqsave(&hss_cache_lock, flags);

    hash_for_each_possible(hss_cache_table, old, node, hash) {
        if (old->pid == pid &&
            old->inode_id == inode_id &&
            old->op_mask == op_mask) {
            hash_del_rcu(&old->node);
            break;
        }
    }

    hash_add_rcu(hss_cache_table, &entry->node, hash);
    if (!old)
        atomic_inc(&hss_cache_count);
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    if (old)
        kfree_rcu(old, rcu);
}

static void hss_cache_invalidate(u32 pid, u64 inode_id, u32 op_mask)
{
    struct hss_cache_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    HLIST_HEAD(garbage);
    u32 hash = hss_cache_hash(pid, inode_id, op_mask);

    spin_lock_irqsave(&hss_cache_lock, flags);
    hash_for_each_possible_safe(hss_cache_table, entry, tmp, node, hash) {
        if (entry->pid == pid &&
            entry->inode_id == inode_id &&
            entry->op_mask == op_mask) {
            hash_del_rcu(&entry->node);
            hlist_add_head(&entry->node, &garbage);
        }
    }
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    hlist_for_each_entry_safe(entry, tmp, &garbage, node) {
        kfree_rcu(entry, rcu);
        atomic_dec(&hss_cache_count);
    }
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

    hlist_for_each_entry_safe(entry, tmp, &garbage, node) {
        kfree_rcu(entry, rcu);
        atomic_dec(&hss_cache_count);
    }
}

/* === Rate limiter ========================================================= */
static bool hss_rate_check(u32 pid, u32 op_mask)
{
    struct hss_rate_entry *entry;
    unsigned long flags;
    unsigned long now = jiffies;
    unsigned long window_start;
    int count;
    u64 key = hss_rate_key(pid, op_mask);

    spin_lock_irqsave(&hss_rate_lock, flags);
    hash_for_each_possible(hss_rate_table, entry, node, key) {
        if (entry->pid == pid && entry->op_mask == op_mask) {
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
        return true;
    }
    entry->pid = pid;
    entry->op_mask = op_mask;
    entry->window_start = now;
    atomic_set(&entry->count, 1);
    hash_add_rcu(hss_rate_table, &entry->node, key);
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
    int fail_count;

    hss_cache_flush_old_entries();
    hss_rate_cleanup_old();
    hss_cache_count_sanity_check();

    /* Circuit breaker decay — zmniejsz o 1 co sekundę */
    fail_count = atomic_read(&hss_upcall_fail_count);
    if (fail_count > 0)
        atomic_dec(&hss_upcall_fail_count);

    mod_timer(&hss_cleanup_timer, round_jiffies(jiffies + HZ));
}

/* === Netlink ============================================================== */
struct hss_nl_invalidate_msg {
    u32 pid;
    u64 inode_id;
    u32 op_mask;
};

static void hss_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct hss_nl_invalidate_msg *msg;

    if (nlh->nlmsg_type != HSS_NL_CMD_INVALIDATE)
        return;

    if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg))
        return;

    if (!netlink_capable(skb, CAP_SYS_ADMIN))
        return;

    msg = nlmsg_data(nlh);
    hss_cache_invalidate(msg->pid, msg->inode_id, msg->op_mask);
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
    struct hss_upcall_msg  msg;
    struct hss_upcall_resp resp = {0};
    struct dentry *dentry;
    u32 pid = (u32)current->pid;
    u64 inode_id;
    u32 op  = 0;
    int ret, cache_ret;

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

    inode_id = ((u64)inode->i_sb->s_dev << 32) | inode->i_ino;

    /* 1. Sprawdź cache */
    cache_ret = hss_cache_lookup(pid, inode_id, op);
    if (cache_ret == 0)
        return 0;
    if (cache_ret == -EACCES)
        return -EACCES;

    /* 2. Circuit breaker (użyj module_param) */
    if (atomic_read(&hss_upcall_fail_count) > hss_circuit_breaker_threshold) {
        pr_warn_ratelimited("holo_lsm: circuit breaker open\n");
        return (op & HSS_OP_WRITE) ? -EACCES : 0;
    }

    /* 3. Rate limit */
    if (!hss_rate_check(pid, op))
        return -EAGAIN;

    /* 4. Przygotuj wiadomość */
    memset(&msg, 0, sizeof(msg));
    msg.timestamp_ns = ktime_get_mono_fast_ns();
    msg.pid          = pid;
    msg.inode_id     = inode_id;
    msg.op_mask      = op;
    get_random_bytes(msg.nonce, sizeof(msg.nonce));

    /* 5. Trylock i upcall */
    if (!mutex_trylock(&hss_sock_mutex)) {
        pr_warn_ratelimited("holo_lsm: socket contention, degraded mode\n");
        return (op & HSS_OP_WRITE) ? -EACCES : 0;
    }

    ret = hss_upcall_locked(&msg, &resp);
    mutex_unlock(&hss_sock_mutex);

    /* 6. Circuit breaker update */
    if (ret < 0 && ret != -EBADMSG)
        atomic_inc(&hss_upcall_fail_count);
    else
        atomic_set(&hss_upcall_fail_count, 0);

    /* 7. Reconnect */
    if (ret == -ENOTCONN) {
        int rc = hss_reconnect();
        if (rc == 0 || rc == -EALREADY)
            return (op & HSS_OP_WRITE) ? -EACCES : 0;
        return (op & HSS_OP_WRITE) ? -EACCES : -EAGAIN;
    }

    if (ret == -ETIMEDOUT)
        return (op & HSS_OP_WRITE) ? -EACCES : -EAGAIN;

    if (ret < 0)
        return -EACCES;

    /* 8. Walidacja odpowiedzi */
    if (resp.decision != 0 && resp.decision != 1)
        return -EACCES;

    if (resp.flags & HSS_FLAG_INVALIDATE_CACHE)
        hss_cache_invalidate(pid, inode_id, op);

    /* 9. Zapisz w cache */
    hss_cache_store(pid, inode_id, op, resp.decision);

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
        mutex_lock(&hss_sock_mutex);
        if (hss_sock) {
            sock_release(hss_sock);
            hss_sock = NULL;
        }
        mutex_unlock(&hss_sock_mutex);
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    timer_setup(&hss_cleanup_timer, hss_cleanup_timer_callback, 0);
    mod_timer(&hss_cleanup_timer, round_jiffies(jiffies + HZ));

    security_add_hooks(holo_hooks, ARRAY_SIZE(holo_hooks), "holo");
    pr_info("HolonOS HSS LSM v4.0 loaded (production ready)\n");
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

    mutex_lock(&hss_sock_mutex);
    if (hss_sock) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }
    mutex_unlock(&hss_sock_mutex);

    if (hss_hmac_tfm)
        crypto_free_shash(hss_hmac_tfm);

    pr_info("HolonOS HSS LSM v4.0 unloaded\n");
}

module_init(holo_lsm_init);
module_exit(holo_lsm_exit);
