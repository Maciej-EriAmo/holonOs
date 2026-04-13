/*
 * security/holo/holo_lsm.c
 *
 * HolonOS HSS LSM — lekki filtr upcall.
 *
 * Jądro NIE przechowuje plaintextu, NIE wykonuje deszyfrowania.
 * Wszystkie decyzje kryptograficzne delegowane są do hss-daemon
 * przez uwierzytelnione gniazdo Unix (HMAC-SHA256).
 *
 * Zgodność z artykułem: "Holographic Session Spaces" v2.5, Sekcja 4.
 * Pseudokod — koncepcyjny szkielet implementacji jądra Linux.
 *
 * Poprawki względem v1:
 *   [1] Naprawiony błąd porównania HMAC ze sobą (dwa oddzielne bufory)
 *   [2] Usunięty martwy hss_pending_resp
 *   [3] Poprawiona kolejność deklaracji holo_hooks[] przed holo_lsm_init()
 *   [4] hss_inode_has_xattr() — stub z komentarzem do __vfs_getxattr
 *   [5] Dodane synchronize_rcu() i cleanup w module_exit
 *
 * Autor: Maciej Mazur — Independent AI Researcher, Warsaw, Poland
 * GitHub: Maciej-EriAmo/HolonOS
 * Licencja: GPL-2.0 (wymagana dla modułów jądra Linux)
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Mazur");
MODULE_DESCRIPTION("HolonOS HSS LSM — upcall filter, no plaintext in kernel");

/* -----------------------------------------------------------------------
 * Parametry konfigurowalne (sysctl w produkcji)
 * ----------------------------------------------------------------------- */
static unsigned int hss_cache_ttl_ms      = 100;   /* TTL pamięci podręcznej */
static unsigned int hss_upcall_timeout_ms = 5;     /* timeout odpowiedzi demona */
static unsigned int hss_rate_limit_per_sec = 100;  /* maks. upcall/sek na PID */

/* -----------------------------------------------------------------------
 * Stałe protokołu
 * ----------------------------------------------------------------------- */
#define HSS_OP_READ    0x01
#define HSS_OP_WRITE   0x02
#define HSS_FLAG_INVALIDATE_CACHE 0x01
#define HSS_XATTR_NAME "security.hss.lock"

/* -----------------------------------------------------------------------
 * Struktury protokołu upcall
 * ----------------------------------------------------------------------- */

/* Wiadomość jądro → demon */
struct hss_upcall_msg {
    u64 timestamp_ns;   /* monotoniczny timestamp (ktime_get_mono_fast_ns) */
    u32 pid;            /* PID procesu wywołującego */
    u32 inode_nr;       /* numer i-węzła */
    u32 op_mask;        /* HSS_OP_READ | HSS_OP_WRITE */
    u8  nonce[16];      /* losowy nonce — ochrona przed replay */
} __packed;

/* Odpowiedź demon → jądro */
struct hss_upcall_resp {
    u8  nonce_echo[16]; /* echo nonce z żądania — weryfikacja spójności */
    u32 decision;       /* 0 = ZEZWÓL, -EACCES = ODMÓW */
    u32 flags;          /* HSS_FLAG_INVALIDATE_CACHE itd. */
} __packed;

/* -----------------------------------------------------------------------
 * Pamięć podręczna decyzji (per-PID + inode, tylko ZEZWOLENIA)
 * ----------------------------------------------------------------------- */
struct hss_cache_entry {
    u32 pid;
    u32 inode_nr;
    u32 op_mask;
    unsigned long expiry_jiffies;
    struct hlist_node node;
    struct rcu_head rcu;    /* potrzebne do kfree_rcu */
};

#define HSS_CACHE_BITS 8
static DEFINE_HASHTABLE(hss_cache_table, HSS_CACHE_BITS);
static DEFINE_SPINLOCK(hss_cache_lock);

static int hss_cache_lookup(u32 pid, u32 inode_nr, u32 op_mask)
{
    struct hss_cache_entry *entry;
    unsigned long now = jiffies;
    u64 key = ((u64)pid << 32) | (u64)inode_nr;
    int ret = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(hss_cache_table, entry, node, key) {
        if (entry->pid == pid && entry->inode_nr == inode_nr &&
            (entry->op_mask & op_mask) == op_mask) {
            if (time_before(now, entry->expiry_jiffies))
                ret = 0; /* trafienie — ZEZWÓL */
            break;
        }
    }
    rcu_read_unlock();
    return ret;
}

static void hss_cache_store(u32 pid, u32 inode_nr, u32 op_mask, u32 decision)
{
    struct hss_cache_entry *entry;
    u64 key = ((u64)pid << 32) | (u64)inode_nr;

    if (decision != 0) /* przechowuj tylko ZEZWOLENIA */
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->pid           = pid;
    entry->inode_nr      = inode_nr;
    entry->op_mask       = op_mask;
    entry->expiry_jiffies = jiffies + msecs_to_jiffies(hss_cache_ttl_ms);

    spin_lock(&hss_cache_lock);
    hash_add_rcu(hss_cache_table, &entry->node, key);
    spin_unlock(&hss_cache_lock);
}

/* Unieważnienie wpisów — wywołane przez demona przez Netlink (TOCTOU fix) */
static void hss_cache_invalidate(u32 pid, u32 inode_nr)
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
    /* synchronize_rcu() — wymagane w produkcji przed zwolnieniem modułu */
}

/* -----------------------------------------------------------------------
 * Ogranicznik szybkości per-PID (rate limiting)
 * ----------------------------------------------------------------------- */
struct hss_rate_entry {
    u32 pid;
    atomic_t count;
    unsigned long window_start;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(hss_rate_table, 6);
static DEFINE_SPINLOCK(hss_rate_lock);

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
static u8 hss_hmac_key[32]; /* ustanawiany przez keyctl z userspace przy starcie */
static DEFINE_MUTEX(hss_sock_mutex);

static int hss_upcall(struct hss_upcall_msg *msg, struct hss_upcall_resp *resp)
{
    struct msghdr mh = {0};
    struct kvec   iov[2];
    /* [FIX 1] Dwa oddzielne bufory HMAC — poprzednia wersja porównywała bufor ze sobą */
    u8 hmac_sent[32];
    u8 hmac_recv_stored[32];  /* HMAC odebrany od demona */
    u8 hmac_recv_computed[32];/* HMAC obliczony lokalnie dla weryfikacji */
    struct hss_upcall_resp tmp;
    int ret;

    if (!hss_sock || !hss_hmac_tfm)
        return -ENOTCONN;

    /* Oblicz i wyślij HMAC wiadomości wychodzącej */
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

    /* Odbierz odpowiedź: [resp][hmac_recv_stored] */
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

    /* [FIX 1] Weryfikacja HMAC odpowiedzi — oblicz na podstawie tmp, porównaj z odebranym */
    {
        SHASH_DESC_ON_STACK(shash, hss_hmac_tfm);
        shash->tfm = hss_hmac_tfm;
        ret = crypto_shash_digest(shash, (u8 *)&tmp, sizeof(tmp),
                                  hmac_recv_computed);
        if (ret)
            goto out_unlock;
    }

    if (crypto_memneq(hmac_recv_stored, hmac_recv_computed, 32)) {
        ret = -EBADMSG; /* HMAC niezgodny — wiadomość zmanipulowana */
        goto out_unlock;
    }

    /* Weryfikacja nonce — ochrona przed replay */
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
static bool hss_inode_has_xattr(struct inode *inode)
{
    /*
     * [FIX 4] Produkcja: użyć __vfs_getxattr() lub inode->i_op->getxattr().
     * Przykład:
     *   char buf[1];
     *   ssize_t sz = __vfs_getxattr(dentry, inode, HSS_XATTR_NAME, buf, 1);
     *   return sz >= 0;
     *
     * Wymaga dostępu do dentry — przekazać przez holo_inode_permission.
     * W poniższym hooku używamy uproszczenia dla szkieletu.
     */
    return inode->i_security != NULL; /* placeholder — zastąpić wywołaniem xattr */
}

/* -----------------------------------------------------------------------
 * Hook LSM: inode_permission
 * Główny punkt egzekucji — wywoływany przy każdym dostępie do i-węzła.
 * Brak plaintextu, brak deszyfrowania. Tylko relay do hss-daemon.
 * ----------------------------------------------------------------------- */
static int holo_inode_permission(struct inode *inode, int mask)
{
    struct hss_upcall_msg  msg  = {0};
    struct hss_upcall_resp resp = {0};
    u32 pid = (u32)current->pid;
    u32 op  = 0;
    int ret;

    /* Obsługujemy tylko read/write — reszta domyślnie dozwolona */
    if (!(mask & (MAY_READ | MAY_WRITE)))
        return 0;

    /* Tylko pliki z xattr security.hss.lock — pozostałe ignorowane */
    if (!hss_inode_has_xattr(inode))
        return 0;

    if (mask & MAY_READ)  op |= HSS_OP_READ;
    if (mask & MAY_WRITE) op |= HSS_OP_WRITE;

    /* 1. Sprawdź cache — hot path */
    if (hss_cache_lookup(pid, (u32)inode->i_ino, op) == 0)
        return 0;

    /* 2. Rate limiting — ochrona przed oracle attacks */
    if (!hss_rate_check(pid))
        return -EAGAIN;

    /* 3. Przygotuj upcall */
    msg.timestamp_ns = ktime_get_mono_fast_ns();
    msg.pid          = pid;
    msg.inode_nr     = (u32)inode->i_ino;
    msg.op_mask      = op;
    get_random_bytes(msg.nonce, sizeof(msg.nonce));

    /* 4. Wyślij do demona i odbierz decyzję */
    ret = hss_upcall(&msg, &resp);
    if (ret == -ENOTCONN || ret == -EAGAIN || ret == -ETIMEDOUT) {
        /* Fail-degraded: demon niedostępny — §4.2 */
        if (op & HSS_OP_WRITE)
            return -EACCES;   /* zapisy zawsze odrzucone przy braku demona */
        return -EAGAIN;       /* odczyty — niech userspace ponowi próbę */
    }
    if (ret < 0)
        return -EACCES;

    /* 5. Unieważnij cache jeśli demon tego zażąda (TOCTOU fix) */
    if (resp.flags & HSS_FLAG_INVALIDATE_CACHE)
        hss_cache_invalidate(pid, (u32)inode->i_ino);

    /* 6. Zapisz zezwolenie w cache */
    hss_cache_store(pid, (u32)inode->i_ino, op, resp.decision);

    /* 7. Zwróć decyzję: 0 = ZEZWÓL, -EACCES = ODMÓW */
    return (int)resp.decision;
}

/* Hook file_open — deleguje do holo_inode_permission */
static int holo_file_open(struct file *file)
{
    int mask = 0;
    if (file->f_flags & (O_WRONLY | O_RDWR)) mask |= MAY_WRITE;
    if (!(file->f_flags & O_WRONLY))         mask |= MAY_READ;
    return holo_inode_permission(file_inode(file), mask);
}

/* -----------------------------------------------------------------------
 * [FIX 3] Deklaracja hooków PRZED holo_lsm_init()
 * ----------------------------------------------------------------------- */
static struct security_hook_list holo_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, holo_inode_permission),
    LSM_HOOK_INIT(file_open,        holo_file_open),
};

/* -----------------------------------------------------------------------
 * Inicjalizacja modułu
 * ----------------------------------------------------------------------- */
static int __init holo_lsm_init(void)
{
    int ret;

    /*
     * 1. Inicjalizacja HMAC-SHA256
     *    Klucz ustawiany przez hss-daemon przez keyctl("hss_upcall_key")
     *    przed zarejestrowaniem hooków.
     */
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

    /*
     * 2. Połącz się z gniazdem demona
     *    Ścieżka: /run/hss-daemon.sock
     *    W produkcji: sock_create + kernel_connect po starcie demona.
     */

    /*
     * 3. Zarejestruj hooki LSM
     */
    security_add_hooks(holo_hooks, ARRAY_SIZE(holo_hooks), "holo");

    pr_info("HolonOS HSS LSM zainicjowany (upcall filter, brak plaintextu w jądrze)\n");
    return 0;
}

/* -----------------------------------------------------------------------
 * [FIX 5] Cleanup modułu — zwalnianie zasobów
 * ----------------------------------------------------------------------- */
static void __exit holo_lsm_exit(void)
{
    struct hss_cache_entry *ce;
    struct hss_rate_entry  *re;
    struct hlist_node *tmp;
    int bkt;

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

    pr_info("HolonOS HSS LSM zatrzymany\n");
}

/* -----------------------------------------------------------------------
 * Netlink handler — komunikacja zwrotna demon → jądro (INVALIDATE_CACHE)
 * ----------------------------------------------------------------------- */
static void hss_netlink_rcv(struct sk_buff *skb)
{
    /*
     * Produkcja: sparsuj wiadomość Netlink { cmd, pid, inode_nr }
     * i wywołaj hss_cache_invalidate(pid, inode_nr).
     * Gwarantuje okno TOCTOU < latencja gniazda (~1µs).
     */
}

module_init(holo_lsm_init);
module_exit(holo_lsm_exit);
