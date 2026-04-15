/*
 * security/holo/holo_lsm.c
 *
 * HolonOS HSS LSM v3.4 — lekki filtr upcall z kontekstem przestrzeni Φ
 *
 * Zmiany v3.4 względem v3.3:
 *   - hss_upcall_msg rozszerzony o phi_session_id i capability_hint
 *     Kernel NIE interpretuje tych pól — przekazuje je nieprzejrzyście do daemona.
 *     Daemon weryfikuje algebraicznie: HMAC(s_A, prism_id) == capability_hint.
 *   - phi_session_id i capability_hint ładowane z kernel keyring per-PID
 *     (agent rejestruje swój kontekst przez keyctl przy starcie)
 *   - s_dev włączone do inode_id dla globalnej unikalności (jak w v4.4)
 *   - netlink_capable(CAP_SYS_ADMIN) dla bezpieczeństwa Netlink
 *   - synchronize_rcu() w exit po zwolnieniu cache
 *   - hss_connect_socket_locked() / hss_connect_socket() rozdzielone
 *
 * ARCHITEKTURA:
 *   Kernel = czysty transport. Zero semantyki HSS w jądrze.
 *   Daemon = weryfikacja algebrą (Ring-LWE, KDF, HMAC).
 *   Φ      = korzeń s_sess z którego wyprowadzone są s_A i capability tokeny.
 *
 *   Pytanie które zadaje kernel:
 *     "agent o tej tożsamości w tej sesji Φ chce dostępu do tego pryzmatu"
 *   Pytanie które zadaje daemon:
 *     "czy HMAC(s_A, prism_id) zgadza się z capability_hint?"
 *
 * Autor: Maciej Mazur — Independent AI Researcher, Warsaw, Poland
 * GitHub: Maciej-EriAmo/HolonOS
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
MODULE_DESCRIPTION("HolonOS HSS LSM v3.4 — upcall filter z kontekstem przestrzeni Phi");

static unsigned int hss_cache_ttl_ms           = 100;
static unsigned int hss_upcall_timeout_ms      = 5;
static unsigned int hss_rate_limit_per_sec     = 100;
static unsigned int hss_reconnect_max_attempts = 3;
static unsigned int hss_reconnect_delay_us     = 50000;

module_param(hss_cache_ttl_ms,           uint, 0644);
module_param(hss_upcall_timeout_ms,      uint, 0644);
module_param(hss_rate_limit_per_sec,     uint, 0644);
module_param(hss_reconnect_max_attempts, uint, 0644);
module_param(hss_reconnect_delay_us,     uint, 0644);

/* -----------------------------------------------------------------------
 * Stałe protokołu
 * ----------------------------------------------------------------------- */
#define HSS_OP_READ               0x01
#define HSS_OP_WRITE              0x02
#define HSS_FLAG_INVALIDATE_CACHE 0x01
#define HSS_XATTR_NAME            "security.hss.lock"
#define HSS_DAEMON_SOCK           "/run/hss-daemon.sock"
#define HSS_KEYRING_NAME          "hss_upcall_key"

/*
 * Nazwy kluczy w kernel keyring dla kontekstu Φ agenta.
 * Agent rejestruje je przez keyctl przy starcie:
 *   keyctl add user hss_phi_session_<PID>    <32-byte phi_session_id>  @s
 *   keyctl add user hss_capability_hint_<PID> <32-byte capability_hint> @s
 *
 * phi_session_id  = H(s_sess || epoch)  — identyfikator sesji Φ
 * capability_hint = HMAC(s_A, prism_id) — token capability agenta
 *
 * Kernel NIE interpretuje tych wartości. Przekazuje je do daemona który
 * weryfikuje algebraicznie bez żadnych list uprawnień.
 */
#define HSS_PHI_SESSION_KEY_PREFIX  "hss_phi_session_"
#define HSS_CAP_HINT_KEY_PREFIX     "hss_capability_hint_"

#define NETLINK_HSS 30
enum { HSS_NL_CMD_INVALIDATE = 1, };

/* -----------------------------------------------------------------------
 * Struktury protokołu upcall
 *
 * Kluczowe pola HSS (v3.4):
 *   phi_session_id  — identyfikuje sesję Φ (z której pochodzi s_A agenta)
 *   capability_hint — token capability agenta: HMAC(s_A, prism_id)
 *                     daemon weryfikuje: recompute == capability_hint → ALLOW
 *
 * Kernel przekazuje te pola nieprzejrzyście.
 * Daemon posiada s_sess i może re-derywować s_A z kontekstu KDF.
 * ----------------------------------------------------------------------- */
struct hss_upcall_msg {
    u64 timestamp_ns;
    u32 pid;
    u64 inode_id;       /* (s_dev << 32) | i_ino — globalnie unikalny */
    u32 op_mask;
    u8  nonce[16];
    /* --- Kontekst przestrzeni Φ (v3.4) --- */
    u8  phi_session_id[32];   /* H(s_sess || epoch) — z keyringu agenta */
    u8  capability_hint[32];  /* HMAC(s_A, prism_id) — daemon weryfikuje */
} __packed;

struct hss_upcall_resp {
    u8  nonce_echo[16];
    u32 decision;   /* 0 = ALLOW, 1 = DENY */
    u32 flags;
} __packed;

/* -----------------------------------------------------------------------
 * Pamięć podręczna decyzji
 * ----------------------------------------------------------------------- */
struct hss_cache_entry {
    u32           pid;
    u64           inode_id;
    u32           op_mask;
    unsigned long expiry_jiffies;
    struct hlist_node node;
    struct rcu_head   rcu;
};

#define HSS_CACHE_BITS 8
static DEFINE_HASHTABLE(hss_cache_table, HSS_CACHE_BITS);
static DEFINE_SPINLOCK(hss_cache_lock);

static int hss_cache_lookup(u32 pid, u64 inode_id, u32 op_mask)
{
    struct hss_cache_entry *entry;
    unsigned long now = jiffies;
    int found = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(hss_cache_table, entry, node, pid ^ inode_id) {
        if (entry->pid == pid &&
            entry->inode_id == inode_id &&
            entry->op_mask == op_mask) {
            found = time_before(now, entry->expiry_jiffies) ? 0 : -ESTALE;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

static void hss_cache_store(u32 pid, u64 inode_id, u32 op_mask, u32 decision)
{
    struct hss_cache_entry *entry, *old = NULL;
    unsigned long flags;

    if (decision != 0)
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->pid           = pid;
    entry->inode_id      = inode_id;
    entry->op_mask       = op_mask;
    entry->expiry_jiffies = jiffies + msecs_to_jiffies(hss_cache_ttl_ms);

    spin_lock_irqsave(&hss_cache_lock, flags);
    hash_for_each_possible(hss_cache_table, old, node, pid ^ inode_id) {
        if (old->pid == pid && old->inode_id == inode_id && old->op_mask == op_mask) {
            hash_del_rcu(&old->node);
            break;
        }
    }
    hash_add_rcu(hss_cache_table, &entry->node, pid ^ inode_id);
    spin_unlock_irqrestore(&hss_cache_lock, flags);

    if (old)
        kfree_rcu(old, rcu);
}

static void hss_cache_invalidate(u32 pid, u64 inode_id)
{
    struct hss_cache_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    HLIST_HEAD(garbage);
    int bkt;

    spin_lock_irqsave(&hss_cache_lock, flags);
    hash_for_each_safe(hss_cache_table, bkt, tmp, entry, node) {
        if ((pid == 0      || entry->pid      == pid)     &&
            (inode_id == 0 || entry->inode_id == inode_id)) {
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

/* -----------------------------------------------------------------------
 * Rate limiter per-PID
 * ----------------------------------------------------------------------- */
struct hss_rate_entry {
    u32           pid;
    atomic_t      count;
    unsigned long window_start;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(hss_rate_table, 6);
static DEFINE_SPINLOCK(hss_rate_lock);

static bool hss_rate_check(u32 pid)
{
    struct hss_rate_entry *entry;
    unsigned long flags;
    unsigned long now = jiffies;
    int count;

    spin_lock_irqsave(&hss_rate_lock, flags);
    hash_for_each_possible(hss_rate_table, entry, node, pid) {
        if (entry->pid == pid) {
            if (time_after(now, entry->window_start + HZ)) {
                entry->window_start = now;
                atomic_set(&entry->count, 1);
                spin_unlock_irqrestore(&hss_rate_lock, flags);
                return true;
            }
            count = atomic_inc_return(&entry->count);
            spin_unlock_irqrestore(&hss_rate_lock, flags);
            return count <= (int)hss_rate_limit_per_sec;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_irqrestore(&hss_rate_lock, flags);
        return true;
    }
    entry->pid          = pid;
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

/* -----------------------------------------------------------------------
 * Timer czyszczący
 * ----------------------------------------------------------------------- */
static struct timer_list hss_cleanup_timer;

static void hss_cleanup_timer_callback(struct timer_list *unused)
{
    hss_cache_flush_old_entries();
    hss_rate_cleanup_old();
    mod_timer(&hss_cleanup_timer, jiffies + HZ);
}

/* -----------------------------------------------------------------------
 * Pobieranie kontekstu Φ z keyringu agenta
 *
 * Agent rejestruje phi_session_id i capability_hint przez keyctl przy starcie.
 * Kernel odczytuje je i dołącza do każdego upcall — daemon weryfikuje algebrą.
 * ----------------------------------------------------------------------- */
static int hss_get_phi_context(u32 pid,
                               u8 phi_session_id[32],
                               u8 capability_hint[32])
{
    struct key *key;
    const struct user_key_payload *payload;
    char keyname[64];
    int ret;

    /* phi_session_id */
    snprintf(keyname, sizeof(keyname), "%s%u", HSS_PHI_SESSION_KEY_PREFIX, pid);
    key = request_key(&key_type_user, keyname, NULL);
    if (IS_ERR(key))
        goto no_context;

    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    ret = (!payload || payload->datalen != 32) ? -EINVAL : 0;
    if (ret == 0)
        memcpy(phi_session_id, payload->data, 32);
    up_read(&key->sem);
    key_put(key);
    if (ret)
        goto no_context;

    /* capability_hint */
    snprintf(keyname, sizeof(keyname), "%s%u", HSS_CAP_HINT_KEY_PREFIX, pid);
    key = request_key(&key_type_user, keyname, NULL);
    if (IS_ERR(key))
        goto no_context;

    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    ret = (!payload || payload->datalen != 32) ? -EINVAL : 0;
    if (ret == 0)
        memcpy(capability_hint, payload->data, 32);
    up_read(&key->sem);
    key_put(key);
    if (ret)
        goto no_context;

    return 0;

no_context:
    /*
     * Agent nie zarejestrował kontekstu Φ.
     * Pola wypełniane zerami — daemon potraktuje jako "brak capability".
     * Jeśli plik wymaga HSS, daemon odmówi dostępu.
     */
    memset(phi_session_id, 0, 32);
    memset(capability_hint, 0, 32);
    return -ENOKEY;
}

/* -----------------------------------------------------------------------
 * Klucz HMAC dla uwierzytelnienia upcall
 * ----------------------------------------------------------------------- */
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

/* -----------------------------------------------------------------------
 * Połączenie z hss-daemon
 * ----------------------------------------------------------------------- */
static struct socket *hss_sock     = NULL;
static struct crypto_shash *hss_hmac_tfm = NULL;
static u8 hss_hmac_key[32];
static DEFINE_MUTEX(hss_sock_mutex);

/* REQUIRES: hss_sock_mutex held */
static int hss_connect_socket_locked(void)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, i;

    strncpy(addr.sun_path, HSS_DAEMON_SOCK, sizeof(addr.sun_path) - 1);

    if (hss_sock) {
        sock_release(hss_sock);
        hss_sock = NULL;
    }

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

static int hss_connect_socket(void)
{
    int ret;
    mutex_lock(&hss_sock_mutex);
    ret = hss_connect_socket_locked();
    mutex_unlock(&hss_sock_mutex);
    return ret;
}

/* -----------------------------------------------------------------------
 * Upcall do hss-daemon (REQUIRES: hss_sock_mutex held)
 * ----------------------------------------------------------------------- */
static int hss_upcall_locked(struct hss_upcall_msg *msg,
                              struct hss_upcall_resp *resp)
{
    struct msghdr mh = {0};
    struct kvec iov[2];
    u8 hmac_sent[32], hmac_recv_stored[32], hmac_recv_computed[32];
    struct hss_upcall_resp tmp = {0};
    long old_timeo;
    int ret;

    if (!hss_hmac_tfm || !hss_sock)
        return -ENOTCONN;

    /* Oblicz HMAC całej wiadomości (w tym phi_session_id i capability_hint) */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)msg, sizeof(*msg), hmac_sent);
        if (ret)
            return ret;
    }

    iov[0].iov_base = msg;       iov[0].iov_len = sizeof(*msg);
    iov[1].iov_base = hmac_sent; iov[1].iov_len = 32;

    ret = kernel_sendmsg(hss_sock, &mh, iov, 2, sizeof(*msg) + 32);
    if (ret != (int)(sizeof(*msg) + 32)) {
        pr_warn_ratelimited("holo_lsm: partial send (%d)\n", ret);
        goto reconnect;
    }

    old_timeo = hss_sock->sk->sk_rcvtimeo;
    hss_sock->sk->sk_rcvtimeo = msecs_to_jiffies(hss_upcall_timeout_ms);

    {
        struct kvec riov[2] = {
            { .iov_base = &tmp,             .iov_len = sizeof(tmp) },
            { .iov_base = hmac_recv_stored, .iov_len = 32          },
        };
        ret = kernel_recvmsg(hss_sock, &mh, riov, 2, sizeof(tmp) + 32, 0);
    }

    hss_sock->sk->sk_rcvtimeo = old_timeo;

    if (ret != (int)(sizeof(tmp) + 32)) {
        pr_warn_ratelimited("holo_lsm: partial recv (%d)\n", ret);
        goto reconnect;
    }

    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)&tmp, sizeof(tmp),
                                  hmac_recv_computed);
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
    return -ENOTCONN;
}

/* -----------------------------------------------------------------------
 * xattr check
 * ----------------------------------------------------------------------- */
static bool hss_inode_has_xattr(struct inode *inode, struct dentry *dentry)
{
    char val;

    if (!inode->i_op || !inode->i_op->getxattr)
        return false;

    return __vfs_getxattr(dentry, inode, HSS_XATTR_NAME, &val, sizeof(val)) >= 0;
}

/* -----------------------------------------------------------------------
 * Netlink — komunikacja zwrotna daemon → kernel (INVALIDATE_CACHE)
 * ----------------------------------------------------------------------- */
static struct sock *hss_nl_sock = NULL;

struct hss_nl_invalidate_msg {
    u32 pid;
    u64 inode_id;
};

static void hss_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct hss_nl_invalidate_msg *msg;

    if (nlh->nlmsg_type != HSS_NL_CMD_INVALIDATE)
        return;
    if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg))
        return;
    /* Tylko CAP_SYS_ADMIN może unieważniać cache — ochrona przed DoS */
    if (!netlink_capable(skb, CAP_SYS_ADMIN))
        return;

    msg = nlmsg_data(nlh);
    hss_cache_invalidate(msg->pid, msg->inode_id);
}

static int __init hss_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = { .input = hss_nl_recv_msg, };
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

/* -----------------------------------------------------------------------
 * Główny hook LSM: inode_permission
 *
 * Kernel przekazuje kontekst Φ (phi_session_id, capability_hint) do daemona.
 * Daemon weryfikuje: HMAC(s_A_recomputed, prism_id) == capability_hint
 * Jeśli tak → ALLOW. Brak list, brak ACL. Czysta algebra.
 * ----------------------------------------------------------------------- */
static struct security_hook_list holo_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, holo_inode_permission),
};

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

    /* inode_id = (s_dev << 32) | i_ino — globalnie unikalny (fix z v4.4) */
    u64 inode_id = ((u64)inode->i_sb->s_dev << 32) | (u64)inode->i_ino;

    /* 1. Cache */
    if (hss_cache_lookup(pid, inode_id, op) == 0)
        return 0;

    /* 2. Rate limit */
    if (!hss_rate_check(pid))
        return -EAGAIN;

    /* 3. Przygotuj wiadomość z kontekstem Φ */
    msg.timestamp_ns = ktime_get_mono_fast_ns();
    msg.pid          = pid;
    msg.inode_id     = inode_id;
    msg.op_mask      = op;
    get_random_bytes(msg.nonce, sizeof(msg.nonce));

    /*
     * Załaduj phi_session_id i capability_hint z keyringu agenta.
     * Brak kontekstu = zera = daemon odmówi dla plików HSS.
     * Nie blokujemy — to jest best-effort w hot path.
     */
    hss_get_phi_context(pid, msg.phi_session_id, msg.capability_hint);

    /* 4. Wyślij upcall (trylock — brak blokowania w hook) */
    if (!mutex_trylock(&hss_sock_mutex))
        return -EAGAIN;

    ret = hss_upcall_locked(&msg, &resp);
    mutex_unlock(&hss_sock_mutex);

    if (ret == -ENOTCONN) {
        /* Spróbuj reconnect w tle — odpowiedź: retry */
        int i;
        for (i = 0; i < (int)hss_reconnect_max_attempts; i++) {
            if (hss_connect_socket() == 0)
                break;
            usleep_range(hss_reconnect_delay_us / 2, hss_reconnect_delay_us);
        }
        return (op & HSS_OP_WRITE) ? -EACCES : -EAGAIN;
    }

    if (ret == -EAGAIN || ret == -ETIMEDOUT)
        return (op & HSS_OP_WRITE) ? -EACCES : -EAGAIN;

    if (ret < 0)
        return -EACCES;

    /* Walidacja decyzji — tylko 0 lub 1 */
    if (resp.decision != 0 && resp.decision != 1)
        return -EACCES;

    if (resp.flags & HSS_FLAG_INVALIDATE_CACHE)
        hss_cache_invalidate(pid, inode_id);

    hss_cache_store(pid, inode_id, op, resp.decision);

    return (resp.decision == 0) ? 0 : -EACCES;
}

/* -----------------------------------------------------------------------
 * Init / Exit
 * ----------------------------------------------------------------------- */
static int __init holo_lsm_init(void)
{
    int ret;

    ret = hss_get_hmac_key();
    if (ret) {
        pr_err("holo_lsm: brak klucza HMAC — dodaj '%s' przez keyctl\n",
               HSS_KEYRING_NAME);
        return ret;
    }

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
        pr_err("holo_lsm: nie można połączyć z %s (ret=%d)\n",
               HSS_DAEMON_SOCK, ret);
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    ret = hss_netlink_init();
    if (ret) {
        mutex_lock(&hss_sock_mutex);
        if (hss_sock) { sock_release(hss_sock); hss_sock = NULL; }
        mutex_unlock(&hss_sock_mutex);
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    timer_setup(&hss_cleanup_timer, hss_cleanup_timer_callback, 0);
    mod_timer(&hss_cleanup_timer, jiffies + HZ);

    security_add_hooks(holo_hooks, ARRAY_SIZE(holo_hooks), "holo");
    pr_info("HolonOS HSS LSM v3.4 loaded "
            "(upcall filter z kontekstem przestrzeni Phi)\n");
    return 0;
}

static void __exit holo_lsm_exit(void)
{
    struct hss_cache_entry *centry;
    struct hss_rate_entry  *rentry;
    struct hlist_node *tmp;
    int bkt;

    del_timer_sync(&hss_cleanup_timer);

    spin_lock_irq(&hss_cache_lock);
    hash_for_each_safe(hss_cache_table, bkt, tmp, centry, node) {
        hash_del_rcu(&centry->node);
        kfree_rcu(centry, rcu);
    }
    spin_unlock_irq(&hss_cache_lock);
    synchronize_rcu();   /* poczekaj na grace period przed zwolnieniem modułu */

    spin_lock_irq(&hss_rate_lock);
    hash_for_each_safe(hss_rate_table, bkt, tmp, rentry, node) {
        hash_del_rcu(&rentry->node);
        kfree_rcu(rentry, rcu);
    }
    spin_unlock_irq(&hss_rate_lock);

    hss_netlink_exit();

    mutex_lock(&hss_sock_mutex);
    if (hss_sock) { sock_release(hss_sock); hss_sock = NULL; }
    mutex_unlock(&hss_sock_mutex);

    if (hss_hmac_tfm)
        crypto_free_shash(hss_hmac_tfm);

    pr_info("HolonOS HSS LSM v3.4 unloaded\n");
}

module_init(holo_lsm_init);
module_exit(holo_lsm_exit);