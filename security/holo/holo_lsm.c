/*
 * security/holo/holo_lsm.c
 *
 * HolonOS HSS LSM — lekki filtr upcall.
 * Wersja finalna (v3) — poprawiona zgodność z API LSM.
 *
 * UWAGA: Aby moduł działał poprawnie, musi zostać **wbudowany w jądro**
 * (np. przez dodanie katalogu security/holo/ do źródeł jądra i włączenie
 * CONFIG_SECURITY_HOLO). Nie można go załadować dynamicznie przez insmod
 * ze względu na __init funkcji rejestracji hooków LSM.
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
#include <linux/time.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Mazur");
MODULE_DESCRIPTION("HolonOS HSS LSM — upcall filter, no plaintext in kernel");

/* -----------------------------------------------------------------------
 * Parametry konfigurowalne (sysctl w produkcji)
 * ----------------------------------------------------------------------- */
static unsigned int hss_cache_ttl_ms      = 100;
static unsigned int hss_upcall_timeout_ms = 5;
static unsigned int hss_rate_limit_per_sec = 100;

module_param(hss_cache_ttl_ms, uint, 0644);
module_param(hss_upcall_timeout_ms, uint, 0644);
module_param(hss_rate_limit_per_sec, uint, 0644);

/* -----------------------------------------------------------------------
 * Stałe protokołu
 * ----------------------------------------------------------------------- */
#define HSS_OP_READ    0x01
#define HSS_OP_WRITE   0x02
#define HSS_FLAG_INVALIDATE_CACHE 0x01
#define HSS_XATTR_NAME "security.hss.lock"

/* Netlink protocol family (custom) */
#define NETLINK_HSS 30

/* Komendy Netlink */
enum {
    HSS_NL_CMD_INVALIDATE = 1,
};

/* -----------------------------------------------------------------------
 * Struktury protokołu upcall
 * ----------------------------------------------------------------------- */
struct hss_upcall_msg {
    u64 timestamp_ns;
    u32 pid;
    unsigned long inode_nr;   /* pełny 64‑bitowy numer i‑węzła */
    u32 op_mask;
    u8  nonce[16];
} __packed;

struct hss_upcall_resp {
    u8  nonce_echo[16];
    u32 decision;            /* 0 = ZEZWÓL, wartość niezerowa = ODMÓW */
    u32 flags;
} __packed;

/* -----------------------------------------------------------------------
 * Pamięć podręczna decyzji (per-PID + inode, tylko ZEZWOLENIA)
 * ----------------------------------------------------------------------- */
struct hss_cache_entry {
    u32 pid;
    unsigned long inode_nr;
    u32 op_mask;
    unsigned long expiry_jiffies;
    struct hlist_node node;
    struct rcu_head rcu;
};

#define HSS_CACHE_BITS 8
static DEFINE_HASHTABLE(hss_cache_table, HSS_CACHE_BITS);
static DEFINE_SPINLOCK(hss_cache_lock);

static int hss_cache_lookup(u32 pid, unsigned long inode_nr, u32 op_mask)
{
    struct hss_cache_entry *entry;
    unsigned long now = jiffies;
    u64 key = ((u64)pid << 32) ^ (u64)inode_nr;
    int ret = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(hss_cache_table, entry, node, key) {
        if (entry->pid == pid && entry->inode_nr == inode_nr &&
            (entry->op_mask & op_mask) == op_mask) {
            if (time_before(now, entry->expiry_jiffies)) {
                ret = 0;
                break;  /* znaleziono ważny wpis */
            }
            /* wpis wygasł — kontynuujemy szukanie (może być inny ważny) */
        }
    }
    rcu_read_unlock();
    return ret;
}

static void hss_cache_store(u32 pid, unsigned long inode_nr, u32 op_mask, u32 decision)
{
    struct hss_cache_entry *entry, *tmp;
    u64 key = ((u64)pid << 32) ^ (u64)inode_nr;

    if (decision != 0)   /* przechowuj tylko ZEZWOLENIA */
        return;

    /* Sprawdź, czy wpis już istnieje (deduplikacja) */
    spin_lock(&hss_cache_lock);
    hash_for_each_possible(hss_cache_table, tmp, node, key) {
        if (tmp->pid == pid && tmp->inode_nr == inode_nr &&
            tmp->op_mask == op_mask) {
            /* Aktualizuj czas wygaśnięcia */
            tmp->expiry_jiffies = jiffies + msecs_to_jiffies(hss_cache_ttl_ms);
            spin_unlock(&hss_cache_lock);
            return;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock(&hss_cache_lock);
        return;
    }

    entry->pid           = pid;
    entry->inode_nr      = inode_nr;
    entry->op_mask       = op_mask;
    entry->expiry_jiffies = jiffies + msecs_to_jiffies(hss_cache_ttl_ms);

    hash_add_rcu(hss_cache_table, &entry->node, key);
    spin_unlock(&hss_cache_lock);
}

/* Unieważnienie wpisów — wywołane przez demona przez Netlink */
static void hss_cache_invalidate(u32 pid, unsigned long inode_nr)
{
    struct hss_cache_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&hss_cache_lock);
    hash_for_each_safe(hss_cache_table, bkt, tmp, entry, node) {
        if ((pid       && entry->pid      == pid)      ||
            (inode_nr  && entry->inode_nr == inode_nr)) {
            hash_del_rcu(&entry->node);
            kfree_rcu(entry, rcu);
        }
    }
    spin_unlock(&hss_cache_lock);
}

/* -----------------------------------------------------------------------
 * Ogranicznik szybkości per-PID (rate limiting) z okresowym czyszczeniem
 * ----------------------------------------------------------------------- */
struct hss_rate_entry {
    u32 pid;
    atomic_t count;
    unsigned long window_start;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(hss_rate_table, 6);
static DEFINE_SPINLOCK(hss_rate_lock);
static struct timer_list hss_rate_cleanup_timer;

static void hss_rate_cleanup(struct timer_list *unused)
{
    struct hss_rate_entry *entry;
    struct hlist_node *tmp;
    unsigned long now = jiffies;
    int bkt;

    spin_lock(&hss_rate_lock);
    hash_for_each_safe(hss_rate_table, bkt, tmp, entry, node) {
        /* Usuwaj wpisy starsze niż 60 sekund od ostatniego okna */
        if (time_after(now, entry->window_start + 60 * HZ)) {
            hash_del(&entry->node);
            kfree(entry);
        }
    }
    spin_unlock(&hss_rate_lock);

    /* Zaplanuj kolejne czyszczenie za 60 sekund */
    mod_timer(&hss_rate_cleanup_timer, jiffies + 60 * HZ);
}

static bool hss_rate_check(u32 pid)
{
    struct hss_rate_entry *rl;
    unsigned long now = jiffies;
    bool allowed = false;

    spin_lock(&hss_rate_lock);
    hash_for_each_possible(hss_rate_table, rl, node, (u64)pid) {
        if (rl->pid != pid)
            continue;
        if (time_after(now, rl->window_start + HZ)) {
            rl->window_start = now;
            atomic_set(&rl->count, 1);
            allowed = true;
        } else if (atomic_read(&rl->count) < (int)hss_rate_limit_per_sec) {
            atomic_inc(&rl->count);
            allowed = true;
        }
        spin_unlock(&hss_rate_lock);
        return allowed;
    }

    /* Nowy PID */
    rl = kmalloc(sizeof(*rl), GFP_ATOMIC);
    if (rl) {
        rl->pid          = pid;
        rl->window_start = now;
        atomic_set(&rl->count, 1);
        hash_add(hss_rate_table, &rl->node, (u64)pid);
        allowed = true;
    }
    spin_unlock(&hss_rate_lock);
    return allowed;
}

/* -----------------------------------------------------------------------
 * Komunikacja z hss-daemon (gniazdo Unix, HMAC-SHA256)
 * ----------------------------------------------------------------------- */
static struct socket  *hss_sock     = NULL;
static struct crypto_shash *hss_hmac_tfm = NULL;
static u8 hss_hmac_key[32]; /* wypełniany z keyringu */
static DEFINE_MUTEX(hss_sock_mutex);

/* Pobranie klucza HMAC z keyringu jądra (użytkownik musi go wcześniej dodać) */
static int hss_get_hmac_key(void)
{
    struct key *key;
    const struct user_key_payload *payload;
    int ret = -ENOKEY;

    key = request_key(&key_type_user, "hss_upcall_key", NULL);
    if (IS_ERR(key))
        return PTR_ERR(key);

    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    if (payload && payload->datalen == 32) {
        memcpy(hss_hmac_key, payload->data, 32);
        ret = 0;
    }
    up_read(&key->sem);
    key_put(key);
    return ret;
}

/* Inicjalizacja gniazda Unix i połączenie z demonem */
static int hss_connect_socket(void)
{
    struct sockaddr_un addr;
    struct timeval tv;
    int ret;

    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &hss_sock);
    if (ret < 0)
        return ret;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/hss-daemon.sock", sizeof(addr.sun_path) - 1);

    ret = kernel_connect(hss_sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        sock_release(hss_sock);
        hss_sock = NULL;
        return ret;
    }

    /* Ustaw timeout odbioru */
    tv.tv_sec  = hss_upcall_timeout_ms / 1000;
    tv.tv_usec = (hss_upcall_timeout_ms % 1000) * 1000;
    kernel_setsockopt(hss_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    return 0;
}

static int hss_upcall(struct hss_upcall_msg *msg, struct hss_upcall_resp *resp)
{
    struct msghdr mh = {0};
    struct kvec   iov[2];
    u8 hmac_sent[32];
    u8 hmac_recv_stored[32];
    u8 hmac_recv_computed[32];
    struct hss_upcall_resp tmp;
    int ret;

    if (!hss_sock || !hss_hmac_tfm)
        return -ENOTCONN;

    /* Oblicz HMAC wiadomości wychodzącej */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)msg, sizeof(*msg), hmac_sent);
        if (ret)
            return ret;
    }

    iov[0].iov_base = msg;        iov[0].iov_len = sizeof(*msg);
    iov[1].iov_base = hmac_sent;  iov[1].iov_len = sizeof(hmac_sent);

    mutex_lock(&hss_sock_mutex);
    ret = kernel_sendmsg(hss_sock, &mh, iov, 2,
                         sizeof(*msg) + sizeof(hmac_sent));
    if (ret < 0)
        goto out_unlock;

    /* Odbierz odpowiedź */
    {
        struct kvec riov[2] = {
            { .iov_base = &tmp,              .iov_len = sizeof(tmp) },
            { .iov_base = hmac_recv_stored,  .iov_len = sizeof(hmac_recv_stored) }
        };
        ret = kernel_recvmsg(hss_sock, &mh, riov, 2,
                             sizeof(tmp) + sizeof(hmac_recv_stored), 0);
        if (ret < 0)
            goto out_unlock;
    }

    /* Weryfikacja HMAC odpowiedzi */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)&tmp, sizeof(tmp),
                                  hmac_recv_computed);
        if (ret)
            goto out_unlock;
    }

    if (crypto_memneq(hmac_recv_stored, hmac_recv_computed, 32)) {
        ret = -EBADMSG;
        goto out_unlock;
    }

    if (memcmp(msg->nonce, tmp.nonce_echo, 16) != 0) {
        ret = -EBADMSG;
        goto out_unlock;
    }

    *resp = tmp;
    ret = 0;

out_unlock:
    mutex_unlock(&hss_sock_mutex);
    return ret;
}

/* -----------------------------------------------------------------------
 * Pomocnicza: sprawdzenie czy i-węzeł ma xattr security.hss.lock
 * ----------------------------------------------------------------------- */
static bool hss_inode_has_xattr(struct inode *inode, struct dentry *dentry)
{
    char val;
    ssize_t ret;

    if (!inode->i_op->getxattr)
        return false;

    ret = __vfs_getxattr(dentry, inode, HSS_XATTR_NAME, &val, sizeof(val));
    return ret >= 0;
}

/* -----------------------------------------------------------------------
 * Hook LSM: inode_permission
 * Główny punkt egzekucji.
 * ----------------------------------------------------------------------- */
static int holo_inode_permission(struct inode *inode, int mask)
{
    struct hss_upcall_msg  msg  = {0};
    struct hss_upcall_resp resp = {0};
    struct dentry *dentry;
    u32 pid = (u32)current->pid;
    u32 op  = 0;
    int ret;

    /* Obsługujemy tylko read/write */
    if (!(mask & (MAY_READ | MAY_WRITE)))
        return 0;

    /* Potrzebujemy dentry do odczytu xattr */
    dentry = d_find_alias(inode);
    if (!dentry)
        return 0;

    /* Tylko pliki z xattr security.hss.lock */
    if (!hss_inode_has_xattr(inode, dentry)) {
        dput(dentry);
        return 0;
    }
    dput(dentry);

    if (mask & MAY_READ)  op |= HSS_OP_READ;
    if (mask & MAY_WRITE) op |= HSS_OP_WRITE;

    /* 1. Cache */
    if (hss_cache_lookup(pid, inode->i_ino, op) == 0)
        return 0;

    /* 2. Rate limiting */
    if (!hss_rate_check(pid))
        return -EAGAIN;

    /* 3. Upcall */
    msg.timestamp_ns = ktime_get_mono_fast_ns();
    msg.pid          = pid;
    msg.inode_nr     = inode->i_ino;
    msg.op_mask      = op;
    get_random_bytes(msg.nonce, sizeof(msg.nonce));

    ret = hss_upcall(&msg, &resp);
    if (ret == -ENOTCONN || ret == -EAGAIN || ret == -ETIMEDOUT) {
        if (op & HSS_OP_WRITE)
            return -EACCES;
        return -EAGAIN;
    }
    if (ret < 0)
        return -EACCES;

    /* 4. Unieważnij cache jeśli demon tego zażądał */
    if (resp.flags & HSS_FLAG_INVALIDATE_CACHE)
        hss_cache_invalidate(pid, inode->i_ino);

    /* 5. Zapisz zezwolenie w cache (tylko jeśli decyzja == 0) */
    hss_cache_store(pid, inode->i_ino, op, resp.decision);

    /* 6. Zwróć decyzję zgodnie z konwencją LSM: 0 = zezwól, -EACCES = odmów */
    if (resp.decision == 0)
        return 0;
    else
        return -EACCES;
}

/* -----------------------------------------------------------------------
 * Netlink handler — komunikacja zwrotna demon → jądro
 * ----------------------------------------------------------------------- */
static struct sock *hss_nl_sock = NULL;

static void hss_netlink_rcv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    u32 *data = NLMSG_DATA(nlh);
    u32 pid;
    u64 inode_nr;

    /* Format: [cmd u32][pid u32][inode_nr u64] */
    if (nlh->nlmsg_len < NLMSG_HDRLEN + 2 * sizeof(u32) + sizeof(u64))
        return;

    if (data[0] == HSS_NL_CMD_INVALIDATE) {
        pid = data[1];
        memcpy(&inode_nr, &data[2], sizeof(u64));
        hss_cache_invalidate(pid, (unsigned long)inode_nr);
    }
}

static int __init hss_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = hss_netlink_rcv,
    };

    hss_nl_sock = netlink_kernel_create(&init_net, NETLINK_HSS, &cfg);
    if (!hss_nl_sock) {
        pr_err("holo_lsm: nie można utworzyć gniazda Netlink\n");
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
 * Deklaracja hooków LSM
 * ----------------------------------------------------------------------- */
static struct security_hook_list holo_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, holo_inode_permission),
    /* file_open nie jest potrzebny – VFS i tak woła inode_permission */
};

/* -----------------------------------------------------------------------
 * Inicjalizacja modułu
 * ----------------------------------------------------------------------- */
static int __init holo_lsm_init(void)
{
    int ret;

    /*
     * UWAGA: Aby moduł działał poprawnie, musi zostać **wbudowany w jądro**.
     * Nie można go załadować przez insmod ze względu na __init funkcji
     * rejestracji hooków LSM (security_add_hooks jest __init).
     */

    /* 1. Pobierz klucz HMAC z keyringu */
    ret = hss_get_hmac_key();
    if (ret) {
        pr_err("holo_lsm: nie można pobrać klucza HMAC (dodaj 'hss_upcall_key' przez keyctl)\n");
        return ret;
    }

    hss_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(hss_hmac_tfm)) {
        pr_err("holo_lsm: nie można zainicjować HMAC-SHA256\n");
        return PTR_ERR(hss_hmac_tfm);
    }

    ret = crypto_shash_setkey(hss_hmac_tfm, hss_hmac_key, sizeof(hss_hmac_key));
    if (ret) {
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    /* 2. Połącz z gniazdem demona */
    ret = hss_connect_socket();
    if (ret) {
        pr_err("holo_lsm: nie można połączyć z /run/hss-daemon.sock (ret=%d)\n", ret);
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    /* 3. Zainicjuj Netlink */
    ret = hss_netlink_init();
    if (ret) {
        sock_release(hss_sock);
        crypto_free_shash(hss_hmac_tfm);
        return ret;
    }

    /* 4. Uruchom timer czyszczenia rate limitera */
    timer_setup(&hss_rate_cleanup_timer, hss_rate_cleanup, 0);
    mod_timer(&hss_rate_cleanup_timer, jiffies + 60 * HZ);

    /* 5. Zarejestruj hooki LSM */
    security_add_hooks(holo_hooks, ARRAY_SIZE(holo_hooks), "holo");

    pr_info("HolonOS HSS LSM v3 zainicjowany (upcall filter, brak plaintextu w jądrze)\n");
    return 0;
}

/* -----------------------------------------------------------------------
 * Cleanup modułu
 * ----------------------------------------------------------------------- */
static void __exit holo_lsm_exit(void)
{
    struct hss_cache_entry *ce;
    struct hss_rate_entry  *re;
    struct hlist_node *tmp;
    int bkt;

    /* Zatrzymaj timer */
    del_timer_sync(&hss_rate_cleanup_timer);

    /* Zwolnij cache */
    spin_lock(&hss_cache_lock);
    hash_for_each_safe(hss_cache_table, bkt, tmp, ce, node) {
        hash_del_rcu(&ce->node);
        kfree_rcu(ce, rcu);
    }
    spin_unlock(&hss_cache_lock);
    synchronize_rcu();

    /* Zwolnij rate limiter */
    spin_lock(&hss_rate_lock);
    hash_for_each_safe(hss_rate_table, bkt, tmp, re, node) {
        hash_del(&re->node);
        kfree(re);
    }
    spin_unlock(&hss_rate_lock);

    /* Zwolnij HMAC */
    if (hss_hmac_tfm)
        crypto_free_shash(hss_hmac_tfm);

    /* Zamknij gniazdo */
    if (hss_sock)
        sock_release(hss_sock);

    /* Zwolnij Netlink */
    hss_netlink_exit();

    pr_info("HolonOS HSS LSM zatrzymany\n");
}

module_init(holo_lsm_init);
module_exit(holo_lsm_exit);
