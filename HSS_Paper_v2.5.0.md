# Holographic Session Spaces: Unifying Process Isolation and Data Access in Cognitive Operating Systems

**Maciej Mazur** — Independent AI Researcher | Warsaw, Poland  
GitHub: Maciej-EriAmo/Holomem  
Version: 2.5.0 | Date: 2026-04-10 | License: CC BY 4.0

---

## Abstract

We propose **Holographic Session Spaces (HSS)**, a unified mechanism for process isolation, temporary storage, and inter-process communication (IPC). In contrast to traditional Discretionary or Mandatory Access Control (DAC/MAC), HSS derives access capabilities directly from the user's private cognitive geometry—the **$\Phi$** state space of the Holon architecture. Each process session receives a unique *session capability token* cryptographically bound to $\Phi$.

A critical innovation is the shift from linear Holographic Reduced Representations (HRR) to the formally hard **Ring Learning with Errors (Ring-LWE)** problem over the polynomial quotient ring $R_q = \mathbb{Z}_q[X]/(X^N + 1)$, following the Lyubashevsky-Peikert-Regev (LPR) construction. We introduce **Dynamic Holographic Task Memory Spaces** regulated by **PrismMasks**: a KDF-based key derivation mechanism that achieves continuously attenuated, partial access without violating RLWE small-polynomial assumptions.

The central thesis of HSS: **an agent exists only within the space defined by a secret-dependent hidden projection operator, and all operations outside that space are informationally zero.** Security is therefore not an external policy layer — it is a topological property of the execution space. Access control becomes an *execution condition*, not a barrier.

Convolution Bleed is formally characterized as a property of polynomial multiplication in $R_q$ (Section 2.3). The kernel LSM module acts as a lightweight **upcall filter**: all cryptographic decisions are delegated to a privileged userspace daemon, ensuring no plaintext ever enters kernel memory.

**Keywords:** Ring-LWE, LPR, capability-based security, process isolation, PrismMask, sparse masking, upcall filter, HolonOS, post-quantum

---

## 1. Introduction

Modern operating systems secure process resources through access control lists (ACLs), user IDs, and mandatory access control frameworks (SELinux, AppArmor). These mechanisms share a fundamental weakness: **they are external to the data they protect**. A compromised process running under the user's UID inherits all of that user's ambient authority, including access to temporary directories (`/tmp`), IPC sockets, and the ability to read sensitive files. Furthermore, these classical mechanisms enforce a binary paradigm—access is either fully granted or completely denied.

The Holon cognitive architecture [Mazur, 2026] introduced a radical alternative: information is not stored as plaintext with external locks, but is **cryptographically bound** to the user's private geometry $\Phi$. HSS extends this principle into the OS kernel.

The system operates across two formally distinct but coupled layers:

1. **The cryptographic layer**: LPR-style RLWE provides IND-CPA–hard capability tokens. Security at this layer is unconditional on any semantic interpretation.
2. **The semantic layer**: The $\Phi$ state space provides a metrized embedding geometry. PrismMasks operate at this layer, using sparse polynomial masking to achieve soft attenuation with bounded SNR degradation in authorized prisms.

A critical design principle in v2.3 is the **no-plaintext-in-kernel** invariant: the LSM module acts solely as an upcall filter, delegating all decryption and policy decisions to a privileged userspace daemon. This resolves the fundamental tension in prior versions between "zero-knowledge kernel mediation" and the computational necessity of decryption.

In this paper, we: (i) establish the LPR cryptographic foundation with properly separated error bounds and authenticated context binding; (ii) provide a formal definition of $\Phi$ with an explicit noise model; (iii) characterize Convolution Bleed and introduce sparse masking to bound SNR degradation in authorized prisms; (iv) describe the corrected upcall-filter kernel architecture; and (v) outline a prism-aware H-IPC extension.

---

## 2. Formal Foundations

### 2.1 Cryptographic Layer: LPR with Authenticated Context Binding

We adopt the LPR public-key encryption scheme [LPR13] over:

$$R_q = \mathbb{Z}_q[X]/(X^N + 1)$$

where $N$ is a power of 2 and $q$ is a prime with $q \equiv 1 \pmod{2N}$.

**Parameter separation.** We distinguish three small-norm distributions:

- $\chi_s$: secret key distribution, $\|s\|_\infty \leq B_s$
- $\chi_e$: error distribution, $\|e\|_\infty \leq B_e$
- $\chi_r$: ephemeral secret distribution, $\|r\|_\infty \leq B_r$

**Key generation.** Secret $s \leftarrow \chi_s$. Public key:

$$b = a \cdot s + e \pmod{q}, \quad a \leftarrow R_q,\quad e \leftarrow \chi_e$$

**Authenticated encryption.** To bind binarized state $\hat{S}_t \in \{0,1\}^N$ to a specific file context, we include an **Additional Authenticated Data (AAD)** field comprising the inode number and session identifier. The plaintext is modified before encryption:

$$\hat{S}_t^{\text{ctx}} = \hat{S}_t \oplus H(\text{inode} \;\|\; \text{session\_id} \;\|\; \text{PrismMask\_policy})$$

where $H$ is a collision-resistant hash (SHA3-256). Encryption then proceeds with $r \leftarrow \chi_r$, $e_1, e_2 \leftarrow \chi_e$:

$$u = a \cdot r + e_1 \pmod{q}$$

$$v = b \cdot r + e_2 + \left\lfloor \frac{q}{2} \right\rfloor \cdot \hat{S}_t^{\text{ctx}} \pmod{q}$$

**Context binding security.** A process holding a valid $s_{\text{sess}}$ but attempting to decrypt a ciphertext created for a different inode or PrismMask policy recovers $\hat{S}_t^{\text{ctx}'} \neq \hat{S}_t^{\text{ctx}}$, since $H(\text{inode}' \| \ldots) \neq H(\text{inode} \| \ldots)$. This prevents Confused Deputy attacks where a high-privilege process is deceived into decrypting low-integrity ciphertexts: the recovered plaintext is cryptographically bound to the expected context and is semantically incoherent if the context mismatches.

**Decryption.** Given correct $s$:

$$\tilde{S} = v - s \cdot u = \lfloor q/2\rfloor \cdot \hat{S}_t^{\text{ctx}} + \underbrace{e \cdot r + e_2 - s \cdot e_1}_{=\,\delta}$$

Correctness condition: $\|\delta\|_\infty \leq B_e(B_r + B_s + 1) < q/4$.

For Kyber-style parameters ($N=256$, $q=3329$, $B_e = B_r = B_s = 2$): $\|\delta\|_\infty \leq 2 \cdot 5 = 10 \ll 832 = q/4$. ✓

The scheme achieves **IND-CPA security** under Decision-RLWE [LPR13].

---

### 2.2 Semantic Layer: The $\Phi$ State Space

**Definition 2.1 (Φ State Space).** The $\Phi$ state space is a tuple $(\mathcal{S}, d, F_\theta, \pi)$ where:

- $\mathcal{S} \subset \mathbb{R}^{L \times k \times d}$ is a compact metric space with $d(S, S') = \|S - S'\|_2$
- $F_\theta: \mathcal{S} \times \mathcal{O} \to \mathcal{S}$ is Lipschitz-continuous with constant $\lambda_F < 1$ (contractive)
- $\pi: \mathcal{S} \to \{0,1\}^N$ is the projection operator defined below.

**State dynamics.**

$$S_{t+1} = F_\theta(S_t, o_t) + \varepsilon_t, \quad \|\varepsilon_t\|_2 \leq \varepsilon_{\max}$$

In the Holon v5.11 implementation, $F_\theta$ is a leaky integrator with KuRz-embedded observations:

$$S_{t+1} = (1 - \eta)\, S_t + \eta\, \hat{o}_t + \varepsilon_t$$

Steady-state noise floor: $\sigma_\infty^2 = \frac{\eta}{2 - \eta} \cdot \sigma_\varepsilon^2$.

**Projection operator with hysteresis (stability fix).** The naive projection $\hat{S}_t = \text{sign}(W_{\text{proj}} \cdot \text{vec}(S_t))$ is unstable near the decision boundary: a state component $p_i = (W_{\text{proj}} \cdot \text{vec}(S_t))[i] \approx 0$ flips bit $i$ under an infinitesimal perturbation $\varepsilon_t$, producing a different capability token and rendering all data encrypted in the prior session irrecoverable. This is the **projection instability problem**.

HSS v2.4 addresses this with two complementary mechanisms:

1. **Frozen session matrix.** At session creation time, the hss-daemon samples $W_{\text{proj}} \leftarrow \mathcal{N}(0, I_{N \times Lkd})$ once and stores it in the session keyring entry. $W_{\text{proj}}$ is immutable for the lifetime of the session. The projection $\hat{S}_{\text{sess}} = \text{sign}(W_{\text{proj}} \cdot \text{vec}(S_{t_0}))$ is computed once at session start from the initial state $S_{t_0}$ and used as the static capability token. Subsequent $\Phi$ dynamics do not alter $\hat{S}_{\text{sess}}$; they affect only the live semantic state, not the cryptographic key material.

2. **Hysteresis band for live re-keying.** When explicit re-keying is required (e.g., at epoch boundaries in the Double Ratchet extension), a hysteresis band of width $2\delta_\pi$ is applied: coefficients with $|p_i| < \delta_\pi$ are not re-binarized but inherit their previous bit value (sticky bit). Only coefficients with $|p_i| \geq \delta_\pi$ produce a new bit. The parameter $\delta_\pi$ is set to $3\sigma_\infty$ (three steady-state standard deviations), ensuring that random-walk perturbations do not cause bit flips with probability $> \Phi_{\text{cdf}}(-3) \approx 0.13\%$ per coefficient per epoch.

Formally, the stable projection is:

$$\hat{S}_t[i] = \begin{cases} \hat{S}_{t-1}[i] & \text{if } |p_i| < \delta_\pi \\ \mathbf{1}[p_i > 0] & \text{otherwise} \end{cases}, \quad p_i = (W_{\text{proj}} \cdot \text{vec}(S_t))[i]$$

This construction reduces bit-flip probability to $< 0.13\%$ per coefficient per epoch, which for $N = 256$ and re-keying intervals $\geq 100$ interactions yields an expected $< 0.33$ bit flips per re-key event—acceptable for error-correcting code recovery if needed.

*Parameter note.* The values $\delta_\pi = 3\sigma_\infty$ and $\kappa = 4$ are heuristically motivated: $3\sigma_\infty$ follows the standard three-sigma rule for Gaussian noise rejection, and $\kappa = 4$ minimizes bleed energy while guaranteeing prism destruction (§2.3). Both values assume a stationary noise floor $\sigma_\infty$. In practice, users with higher cognitive state variance (e.g., high-arousal or high-distraction profiles) will exhibit a larger effective $\sigma_\infty$, which raises the required $\delta_\pi$ and potentially increases the re-keying epoch frequency. A future extension to HSS (planned for PoC v2) will support **adaptive projection parameters**: the hss-daemon estimates $\hat{\sigma}_\infty$ from a rolling window of $\Phi$ state samples and adjusts $\delta_\pi$ online, decoupling key stability from user-specific cognitive dynamics. Formal characterization of parameter sensitivity across user profiles is identified as an open empirical research question.

**Separation theorem.** IND-CPA security of the RLWE scheme holds for any distribution of $\hat{S}_t$, independent of $\Phi$ dynamics. The semantic and cryptographic layers impose no joint assumptions.

---

### 2.3 Convolution Bleed: Formal Characterization and KDF-Based Attenuation

**Note on NTT and polynomial multiplication.** Convolution Bleed arises from polynomial multiplication in $R_q$, not from the NTT algorithm per se. The global mixing property holds in the coefficient representation as well.

**Lemma 2.2 (Global Mixing).** Let $f, g \in R_q$ with $g \neq 0$. The product $h = f \cdot g \pmod{X^N + 1}$ satisfies:

$$h[k] = \sum_{j=0}^{N-1} f[j] \cdot g[(k-j) \bmod N] \cdot (-1)^{\lfloor (k-j+N)/N \rfloor}$$

If $f$ is supported on a single index $j_0$, then $h[k] = f[j_0] \cdot g[(k-j_0) \bmod N] \cdot (\pm 1)$, which is generically nonzero for all $k$ whenever $g$ has no zero coefficients mod $q$. $\square$

**Corollary 2.3 (Convolution Bleed).** Let $m_j \in R_q$ be supported on prism $\mathcal{P}_j \subset [N]$. Any decryption error $\Delta = m_j \cdot u$ has generically full support on $[N]$, including indices outside $\mathcal{P}_j$.

**Prior approach and its flaw.** Earlier versions of HSS applied attenuation by directly modifying the secret key: $s' = s + m_j^{\text{sparse}}$. This has a critical security flaw identified by peer review: an adversary who obtains multiple attenuated keys $s, s', s'', \ldots$ for different policies can compute their differences to recover the masking polynomials $m_j$. These differences leak structural information about the prism partition, potentially enabling attacks that reconstruct unauthorized prisms. Modifying the key also risks correlation between parent and child keys that falls outside the standard RLWE security proof.

**KDF-based attenuation (v2.5 correction).** The correct approach moves masking entirely off the key and onto a per-policy key derivation. The parent's secret $s$ is never modified. Instead, each policy context receives an independent derived key:

$$s_{\text{policy}} = \text{KDF}(s_{\text{sess}},\; \text{policy\_id},\; \text{prism\_set}) \pmod{q}$$

where $\text{policy\_id}$ is a unique identifier for the access policy and $\text{prism\_set} \subseteq \{\mathcal{P}_1, \ldots, \mathcal{P}_K\}$ is the set of authorized prisms. The KDF (HKDF-SHA3-256) produces an output that is computationally indistinguishable from uniform in $R_q$ given only $\text{policy\_id}$ and $\text{prism\_set}$, without knowledge of $s_{\text{sess}}$. This provides two guarantees:

1. **Key independence**: $s_{\text{policy}}$ and $s_{\text{sess}}$ are computationally uncorrelated; an adversary holding multiple $s_{\text{policy}}$ values cannot recover $s_{\text{sess}}$ or any other policy key (under PRF security of HKDF).
2. **Distribution preservation**: $s_{\text{policy}}$ is uniformly distributed in $R_q$ modulo the small-norm truncation, satisfying RLWE secret requirements independently of whether $s_{\text{sess}}$ was small.

**Attenuation via ciphertext re-encryption.** Prism-level access control is enforced not by key degradation but by **selective re-encryption**: data in authorized prisms $\mathcal{P}_{\text{allow}}$ is re-encrypted under $s_{\text{policy}}$ by the hss-daemon before delivery; data in masked prisms $\mathcal{P}_{\text{deny}}$ is replaced with fresh LPR encryptions of zero under a one-time key unknown to the child process. The child decrypts authorized prisms coherently and recovers zero-noise for masked prisms—indistinguishable from a genuine low-signal state.

Formally, for each prism $\mathcal{P}_j$:

$$\text{ciphertext}_j^{\text{child}} = \begin{cases} \text{LPR.ReEnc}(s_{\text{sess}} \to s_{\text{policy}},\; \text{ct}_j) & \text{if } \mathcal{P}_j \in \mathcal{P}_{\text{allow}} \\ \text{LPR.Enc}(k_{\text{one-time}},\; \mathbf{0}) & \text{if } \mathcal{P}_j \in \mathcal{P}_{\text{deny}} \end{cases}$$

The re-encryption $\text{LPR.ReEnc}$ is performed by the hss-daemon, which holds both $s_{\text{sess}}$ and $s_{\text{policy}}$; it decrypts under $s_{\text{sess}}$ and re-encrypts under $s_{\text{policy}}$ in a single atomic userspace operation. No plaintext is held in kernel memory.

**SNR analysis.** Under this construction there is no Convolution Bleed into authorized prisms at the key level, since the key is never modified. The child's $s_{\text{policy}}$ correctly decrypts authorized prisms with full SNR. Masked prisms decrypt to zero (encrypted noise), producing $\text{SNR} = 0$ for those axes — a clean hard boundary rather than a probabilistic one.

---

## 3. Holographic Session Spaces: Capability Model

### 3.1 The Session Capability Token and Epoch Rotation

Every interactive session is associated with the user's private $\Phi^2$. The hss-daemon maintains a **base secret** and derives an **epoch secret** rotated every $T_{\text{epoch}}$ seconds (default 300s):

$$s_{\text{sess}} = \text{HMAC}(\text{base\_secret},\; \text{epoch}) \pmod{q}, \quad \text{epoch} = \lfloor t / T_{\text{epoch}} \rfloor$$

Epoch rotation provides **inter-epoch forward secrecy**: compromise of $s_{\text{sess}}$ at epoch $e$ does not expose secrets from prior epochs. The `base_secret` is immutable for the session lifetime and stored exclusively in the kernel keyring.

Agent capability keys are derived via JSON-encoded context, eliminating string-injection attacks:

$$s_A = \text{KDF}(s_{\text{sess}},\; \text{JSON}(\{\text{"task"}: \text{task\_id},\; \text{"prisms"}: \mathcal{P}_{\text{allow}}\}))$$

Capability verification uses set membership: $\text{prism\_id} \in \mathcal{P}_{\text{allow}}$ must be an exact element, not a prefix or substring.

### 3.2 Data Perception as Decryption

Data written by a process is encrypted under $s_{\text{sess}}$ with context binding (Section 2.1). The ciphertext $(u_t, v_t)$ is stored in `security.hss.lock` xattr. Decryption is performed exclusively by the hss-daemon in protected userspace; the LSM module never receives or stores plaintext (Section 4).

An unauthorized process holding $s' \neq s_{\text{sess}}$ recovers a value computationally indistinguishable from uniform noise under Decision-RLWE. A process holding valid $s_{\text{sess}}$ but targeting a mismatched inode recovers semantically incoherent plaintext due to context binding. Both cases are indistinguishable from noise to the unauthorized process.

### 3.3 Dynamic Holographic Task Memory Spaces

A **Dynamic Holographic Task Memory Space** is an isolated cryptographic context created at task launch:

$$(u_t,\, v_t) = \text{LPR.Enc}(s_{\text{sess}},\; \pi(S_t),\; \text{AAD}_t)$$

where $\text{AAD}_t = H(\text{inode}_t \| \text{session\_id} \| \text{PrismPolicy}_t)$.

On task termination, the hss-daemon erases $s_{\text{sess}}$ from the keyring entry associated with the task's PID. The ciphertext remains on disk but is irrecoverable without the erased key.

### 3.4 PrismMasks and KDF-Based Attenuation

When a parent process spawns a child requiring restricted access, the hss-daemon derives a policy-specific key using the KDF construction of Section 2.3:

$$s_{\text{policy}} = \text{KDF}(s_{\text{sess}},\; \text{policy\_id},\; \mathcal{P}_{\text{allow}})$$

The child process receives $s_{\text{policy}}$ in its keyring entry. The hss-daemon performs selective re-encryption: authorized prisms are re-encrypted under $s_{\text{policy}}$; denied prisms receive fresh encryptions of zero under ephemeral one-time keys. The child decrypts all prisms using $s_{\text{policy}}$, coherently recovering authorized content and zero-signal for denied prisms.

**Security properties of KDF derivation:**

- Multiple policy keys $s_{\text{policy}}, s_{\text{policy}'}, \ldots$ are mutually computationally independent under PRF security of HKDF; their differences reveal nothing about $s_{\text{sess}}$ or each other.
- The parent's $s_{\text{sess}}$ is never transmitted to or derivable by the child.
- The child cannot escalate privileges by manipulating its own $s_{\text{policy}}$: the AAD context binding (Section 2.1) includes the policy\_id, so a child attempting to re-use a different policy's ciphertext recovers incoherent plaintext.

**Capability tree.** Policy derivation is transitive: a child can further delegate to a grandchild with a subset of its own $\mathcal{P}_{\text{allow}}$:

$$s_{\text{grandchild}} = \text{KDF}(s_{\text{policy}},\; \text{policy\_id}',\; \mathcal{P}_{\text{allow}}' \subseteq \mathcal{P}_{\text{allow}})$$

This defines a **capability tree** rooted at $\Phi$'s $s_{\text{sess}}$, where each edge is a KDF step and each node has strictly non-increasing access to the prism partition. A node cannot grant its children access to prisms it does not itself hold.

### 3.5 Program Execution Space: Agent Lifecycle in HolonOS

HSS provides the cryptographic foundation for a key HolonOS capability: the ability to **synthesize, execute, and isolate programs on demand** in response to user intent. This section describes the execution model that HSS enables.

**Motivation.** HolonOS is designed as an agent-first cognitive operating system. Rather than running a fixed set of applications, $\Phi$ synthesizes task-specific programs (agents) when needed—e.g., an email agent, a calendar agent, a web retrieval agent—and terminates them upon task completion. Each synthesized agent must be: (i) isolated from $\Phi$'s core cognitive state; (ii) limited to exactly the resources its task requires; (iii) incapable of modifying its creator. HSS provides all three properties through its capability tree.

**Agent as capability subtree.** When $\Phi$ decides to launch agent $A$ for task $T$, the hss-daemon derives an agent capability key:

$$s_A = \text{KDF}(s_{\text{sess}},\; \text{agent\_id}_A,\; \mathcal{P}_{\text{task}(T)})$$

where $\mathcal{P}_{\text{task}(T)} \subseteq \{\mathcal{P}_1, \ldots, \mathcal{P}_K\}$ is the minimal prism set required for task $T$ (principle of least privilege). Agent $A$ can read and write only within its authorized prisms. $\Phi$'s core state ($\Phi^2$, episodic memory, emotional axes) resides in prisms not granted to $A$; these are cryptographically invisible to $A$.

**Agent lifecycle:**

```
Φ identifies need for task T
        ↓
hss-daemon derives s_A = KDF(s_sess, agent_id, P_task)
        ↓
Agent A launched with s_A in keyring (no access to s_sess)
        ↓
Agent A executes: reads/writes only P_task prisms
        ↓
Result written to P_result prism (readable by Φ)
        ↓
Task complete: s_A erased from keyring, agent terminated
        ↓
Φ reads result from P_result using s_sess
```

**Write-protection of Φ core.** Agent $A$ holds $s_A$ which authorizes writes only to $\mathcal{P}_{\text{task}(T)}$. The AAD context binding includes the agent\_id and task\_id; any attempt by $A$ to write to a prism outside $\mathcal{P}_{\text{task}(T)}$ produces a ciphertext with mismatched AAD that the hss-daemon rejects. A malicious or buggy agent cannot write to $\Phi$'s cognitive state even if it attempts to do so. This is the key guarantee that distinguishes HSS-enabled HolonOS from current agent frameworks: **generated code cannot modify its creator's state by construction, not by convention.**

**Credential prism.** Tasks requiring external authentication (e.g., email via SMTP/OAuth, API calls) need access to secrets that must be: isolated from $\Phi$'s semantic memory, not visible to other agents, and not returned to $\Phi$ as plaintext. HSS provides this through a **credential prism** $\mathcal{P}_{\text{cred}}$: a dedicated prism whose content is sealed at provisioning time and accessible only to agents whose policy explicitly includes $\mathcal{P}_{\text{cred}}$. The prism derives from a separate root:

$$s_{\text{cred}} = \text{KDF}(s_{\text{hw}},\; \text{"hss-cred-v1"},\; \text{service\_id})$$

where $s_{\text{hw}}$ is a hardware-backed secret (TPM primary key or TrustZone TA secret). Credentials are thus sealed to hardware and isolated even from $\Phi$'s main session key. An email agent receives $K_{\text{cred}}$ for the SMTP service; a web agent receives $K_{\text{cred}}$ for the target API; neither can cross-access the other's credentials.

**Agent types.** The model supports three agent classes:

| Type | Lifetime | State | Example |
|---|---|---|---|
| **Ephemeral** | Single task, terminates | None persisted | Send email, fetch URL |
| **Hibernating** | Suspended between activations | Persisted in $\mathcal{P}_{\text{task}}$ | Calendar monitor, reminder watcher |
| **Persistent** | Runs continuously | Full state in own prism subtree | Background indexer, sync agent |

All three classes share the same capability isolation guarantees. Hibernating agents serialize their state to HSS-encrypted files in $\mathcal{P}_{\text{task}}$ on suspension; the state is irrecoverable without $s_A$, which is re-derived from $s_{\text{sess}}$ on wakeup.

The central architectural correction in v2.3 is the elimination of all cryptographic computation from kernel space. **No plaintext ever enters kernel memory.** The LSM module `security_holo` acts solely as an **upcall filter**: it intercepts VFS operations and delegates the access decision to the hss-daemon via an authenticated Unix socket.

### 4.1 Architecture Overview

```
┌───────────────────────────────────────────────────────┐
│                    User Space                         │
│  ┌─────────────────────────────────────────────────┐ │
│  │              hss-daemon (privileged)            │ │
│  │                                                 │ │
│  │  Receives upcall: (PID, inode, operation)       │ │
│  │  1. Fetch s_sess from kernel keyring (PID)      │ │
│  │  2. Fetch (a, u, v) from inode xattr            │ │
│  │  3. LPR.Dec → S̃  (NTT polynomial mult.)        │ │
│  │  4. Verify AAD context binding                  │ │
│  │  5. Compute σ²(S̃)                              │ │
│  │  6. Decision:                                   │ │
│  │     • σ² < θ  → ALLOW (+ re-encrypt for child) │ │
│  │     • σ² ≥ θ  → DENY                           │ │
│  │  7. Return allow/deny to LSM via socket reply   │ │
│  └────────────────────┬────────────────────────────┘ │
│                       │  Unix socket (HMAC-auth'd)    │
└───────────────────────┼───────────────────────────────┘
                        │
┌───────────────────────┼───────────────────────────────┐
│                  Kernel Space                         │
│  ┌────────────────────▼────────────────────────────┐ │
│  │         security_holo (LSM upcall filter)       │ │
│  │                                                 │ │
│  │  security_inode_permission / security_file_open │ │
│  │  → send upcall(PID, inode, op) to hss-daemon    │ │
│  │  → await allow/deny response                    │ │
│  │  → enforce POSIX -EACCES on deny                │ │
│  │                                                 │ │
│  │  NO PLAINTEXT. NO DECRYPTION. NO VARIANCE.      │ │
│  └─────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────┐ │
│  │     HolonFS overlay (VFS xattr layer)           │ │
│  │     security.hss.lock  = { a, u, v } ∈ R_q     │ │
│  │     security.hss.policy = PrismPolicy blob      │ │
│  │     security.hss.threshold = θ                  │ │
│  └─────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

### 4.2 Upcall Protocol

The upcall protocol between `security_holo` and the hss-daemon is:

1. LSM hook fires on `security_inode_permission(inode, mask)`.
2. LSM sends a signed upcall message: `{ pid, inode_nr, op_mask, timestamp }` over the authenticated Unix socket.
3. hss-daemon performs decryption, context binding verification, and **blinded variance check** in userspace (see below).
4. hss-daemon returns `{ decision: ALLOW | DENY, nonce: u64 }`.
5. LSM verifies the nonce matches the outstanding upcall, then enforces the decision.

The socket is authenticated via HMAC-SHA256 with a key established at daemon startup through the kernel keyring, preventing any unprivileged process from injecting allow/deny responses.

**Blinded variance check.** The bare variance decision $\sigma^2(\tilde{S}) < \theta \Rightarrow \text{ALLOW}$ creates a decryption oracle: an adversary can submit manipulated ciphertexts and observe ALLOW/DENY to recover information about the plaintext via binary search. HSS v2.5 eliminates this oracle through two mechanisms:

**(a) Noise injection.** Before the variance is evaluated, the daemon adds calibrated Gaussian noise $\xi \sim \mathcal{N}(0, \sigma_\xi^2)$ to the recovered $\tilde{S}$, where $\sigma_\xi = \beta \cdot \theta$ for a blinding factor $\beta \in (0.05, 0.1)$. The effective decision boundary becomes $\sigma^2(\tilde{S} + \xi) < \theta$, which is stochastic: legitimate decryptions (low $\sigma^2$) pass with probability $> 1 - 10^{-6}$, while adversarially crafted borderline ciphertexts produce inconsistent ALLOW/DENY responses that reveal no exploitable gradient.

**(b) Rate limiting.** The hss-daemon enforces a per-PID decision rate limit of $R_{\max} = 100$ upcalls/second. Requests exceeding this rate receive `-EAGAIN` with exponential backoff. This bounds the adversary's oracle query throughput to $O(100)$ bits/second of information leakage—insufficient for practical key recovery against a 256-bit secret within any realistic window.

The combination of noise injection and rate limiting reduces the oracle attack to a computationally infeasible proposition: recovering $N = 256$ bits at 100 queries/second with noisy responses requires $\Omega(2^{128})$ queries in expectation.

**Performance.** The synchronous upcall adds one IPC round-trip per file access on the cold path. Hot-path optimization: the hss-daemon maintains a per-PID allow-cache of recently accessed inodes (TTL: 100ms), reducing cold-path upcalls to cache misses only. Estimated latency: $\approx 50\,\mu\text{s}$ (cold, including NTT) and $< 1\,\mu\text{s}$ (cached). For cognitive data streams (non-binary), the daemon passes the noisy decrypted state directly to the process via a shared-memory region, bypassing the kernel entirely for data transfer.

**TOCTOU and cache invalidation.** The allow-cache introduces a time-of-check vs. time-of-use (TOCTOU) window: if the PrismPolicy of a task changes between a cache entry's creation and its use (e.g., a parent revokes a child's prism access), the child may retain cached ALLOW decisions for up to the TTL duration. Mitigation: policy changes trigger an explicit cache invalidation message from the hss-daemon to the LSM module via a dedicated `policy_invalidate(PID, inode)` upcall, reducing the TOCTOU window to the socket round-trip latency ($< 1\,\mu\text{s}$) rather than the TTL.

**Daemon fault resilience (SPOF mitigation).** The hss-daemon is a privileged single process; its crash renders all HSS-protected files inaccessible because the LSM module cannot issue ALLOW decisions without a daemon response. HSS addresses this as follows:

- The hss-daemon is managed by systemd with `Restart=always` and `RestartSec=50ms`. Session keys are stored in the kernel keyring (not in daemon heap memory), so they survive a daemon crash and are immediately accessible to the restarted daemon.
- On upcall timeout (no response within 5ms), the LSM module applies a **fail-degraded policy**: read operations on already-opened file descriptors return `-EAGAIN` (retry); new `open()` calls for write return `-EACCES`; read-only `open()` calls are queued for 500ms pending daemon recovery. This ensures the system remains readable during a transient daemon restart while preventing new writes that would produce irrecoverable ciphertexts.
- A watchdog thread in the hss-daemon flushes the keyring to a TPM-sealed backup every 30 seconds; on restart, the daemon recovers the keyring state from the backup before accepting new upcalls.

**Concurrency during restart window.** During the 500ms read-queue window, concurrent writers and readers on the same inode are serialized by the standard VFS inode lock (`inode->i_rwsem`). HSS does not introduce an additional lock manager: semantic access serialization is a consequence of existing VFS locking, which holds across the restart window. A process queued for read that wakes after a concurrent writer has re-encrypted the file under a new epoch key will encounter a ciphertext with a different `session_id` in the AAD; the hss-daemon will detect the mismatch and return the updated decryption using the new epoch key if the process holds the appropriate capability. This ensures read-after-write consistency without HSS-specific locking.

**Watchdog protocol independence.** The daemon restart mechanism is described using systemd as the reference implementation, but the underlying watchdog protocol is implementation-agnostic: any supervisor that monitors the hss-daemon's Unix socket liveness (via a periodic `PING`/`PONG` exchange) and restarts the process on timeout implements the required behavior. This applies equally to embedded environments (e.g., s6, runit, or a bare `fork()`/`waitpid()` supervisor loop) and OCI container runtimes where systemd is unavailable.

### 4.3 Relationship to Prior "Zero-Knowledge" Claim

Prior versions claimed the kernel module performed "zero-knowledge semantic mediation." This claim was incorrect: computing $\sigma^2(\tilde{S})$ requires decryption, which requires $s_{\text{sess}}$, which cannot reside in the kernel without exposing plaintext. The corrected architecture is explicit: **the kernel is a policy-enforcement relay, not a cryptographic oracle.** The hss-daemon is the true point of policy enforcement; the kernel module ensures that enforcement cannot be bypassed by userspace.

---

## 5. Holographic IPC (H-IPC) with Prism-Aware Attenuation

### 5.1 Base Channel: KEM with Forward Secrecy

HSS establishes shared channels via a two-message KEM protocol (corrected from v2.0's invalid $s_A \cdot s_B$ construction):

1. $A$ generates ephemeral keypair: $s_{\text{ch}} \leftarrow \chi_s$, $b_{\text{ch}} = a_{\text{ch}} \cdot s_{\text{ch}} + e_{\text{ch}}$, transmits $(a_{\text{ch}}, b_{\text{ch}})$.
2. $B$ encapsulates: $r_B \leftarrow \chi_r$, $(u_K, v_K) = \text{LPR.Enc}(b_{\text{ch}}, K)$ for fresh $K \in \{0,1\}^\lambda$.
3. $A$ decapsulates: $K = \text{LPR.Dec}(s_{\text{ch}}, u_K, v_K)$.
4. Shared token: $s_{\text{shared}} = \text{KDF}(K, \text{"hss-ipc-v1"}, \text{nonce})$.

$s_{\text{ch}}$ is erased after step 3, providing **per-session forward secrecy**.

### 5.2 Prism-Aware IPC Attenuation

The base KEM establishes a full-capability shared secret $K$. Rather than degrading $s_{\text{shared}}$ additively (which inherits the correlated-key problems of the prior PrismMask construction), HSS v2.5 derives independent per-prism channel keys:

$$K_j = \text{KDF}(K,\; \text{"hss-ipc-prism"},\; j), \quad j \in \{1, \ldots, K_{\text{total}}\}$$

Process $A$ selectively transmits only the $K_j$ values for prisms in $\mathcal{P}_{\text{allow}}$ to process $B$. Each $K_j$ is independently encrypted under $B$'s long-term public key before transmission. Process $B$ derives its session token for each authorized prism independently:

$$s_{\text{shared},j}^B = \text{KDF}(K_j,\; \text{"hss-ipc-sess"},\; \text{nonce})$$

Messages on the channel are bound per-prism: a message touching prism $\mathcal{P}_j$ is encrypted under $s_{\text{shared},j}^B$. Process $B$ can decrypt only the prisms for which it received $K_j$.

**Security properties:** Each $K_j$ is computationally independent under PRF security of KDF; knowing $K_{j_1}$ reveals nothing about $K_{j_2}$ for $j_1 \neq j_2$. Process $B$ cannot reconstruct unauthorized $K_j$ values or escalate to full $K$. Forward secrecy holds per prism: revoking $K_j$ from $B$ requires only re-keying that prism's channel without disturbing others.

**Note on Attribute-Based Encryption (ABE).** Per-prism KDF correctly expresses OR-semantics (access to prism $j$ OR prism $k$). Boolean AND-conjunctions (access requires BOTH prism $j$ AND prism $k$) require ABE [Sahai-Waters, 2005] or a multi-key threshold scheme. This is identified as a primary target for HSS v3.0.

---

## 6. Security Analysis

### 6.1 Threat Model

We assume a Dolev-Yao adversary who can: execute arbitrary code under the same UID; read raw disk blocks and xattr fields; sniff all local IPC traffic; obtain source code of `security_holo` and hss-daemon. The adversary **cannot**: extract secrets from the kernel keyring without root privileges; modify kernel memory; solve Decision-RLWE in polynomial time.

### 6.2 Resistance to Common Attacks

| Attack Vector | Traditional Mitigation | HSS Mitigation |
|---|---|---|
| **Process reading `/tmp`** | DAC permissions | Ciphertext is IND-CPA; without $s_{\text{sess}}$, decryption yields noise. |
| **Confused Deputy** | Sandboxing | AAD context binding (inode ‖ session ‖ policy\_id) ties ciphertext to intended consumer; wrong-context decryption yields incoherent plaintext. |
| **Correlated policy key attack** | — | KDF-derived $s_{\text{policy}}$ keys are mutually independent under PRF; differences reveal nothing about $s_{\text{sess}}$. |
| **Variance oracle** | — | Blinded variance (noise injection $\sigma_\xi = 0.05\theta$) + rate limiting (100 req/s) reduces oracle throughput to $< 100$ bits/s—infeasible for key recovery. |
| **IPC eavesdropping** | Socket permissions | KEM-encrypted $K$; per-prism $K_j = \text{KDF}(K, j)$ independently secured. |
| **Child accessing parent prisms** | Namespaces | KDF isolation: $s_{\text{policy}}$ cannot recover $s_{\text{sess}}$; denied prisms receive zero-encryptions under one-time keys. |
| **Agent modifying Φ core** | Convention / sandboxing | AAD includes agent\_id + task\_id; writes outside $\mathcal{P}_{\text{task}}$ produce mismatched AAD, rejected by hss-daemon. |
| **Credential cross-access** | Application-level isolation | Credential prism $\mathcal{P}_{\text{cred}}$ keyed from hardware root $s_{\text{hw}}$; per-service $K_{\text{cred}}$ independently derived. |
| **Replay on H-IPC** | Sequence numbers | Nonce in KDF input; replayed ciphertext produces a different $s_{\text{shared},j}$. |
| **LSM bypass by userspace** | — | Upcall socket is HMAC-authenticated; unprivileged processes cannot inject allow responses. |

### 6.3 Security Boundaries and Explicit Limitations

HSS provides **inter-process boundary protection** and **data-at-rest protection against offline theft**. It explicitly does **not** provide:

- **Root protection**: If an attacker achieves root (UID 0), they can access the kernel keyring directly via `keyctl`, obtain $s_{\text{sess}}$, and decrypt all files. Alternatively, root can patch the LSM module or terminate the hss-daemon. **HSS offers zero protection against a compromised root.** This is a fundamental limitation of any purely OS-level security mechanism. Hardware-backed key storage (TPM 2.0, ARM TrustZone, or AMD SEV-SNP) is **required**—not merely planned—for any deployment where adversarial root access is part of the threat model. In such configurations, $s_{\text{sess}}$ is sealed to a PCR measurement and cannot be extracted even by root; AMD SEV-SNP additionally encrypts VM memory pages, extending the boundary against hypervisor-level attackers. Without hardware sealing, HSS is a defense-in-depth mechanism protecting against non-privileged attackers only.
- **Post-decryption confidentiality**: An authorized process that has decrypted data can leak the plaintext through any channel. Mitigation requires IFC [Myers-Liskov, 1997].
- **Hypervisor boundary**: A virtual machine monitor with access to physical memory can extract the keyring regardless of HSS. HSS is a defense-in-depth mechanism, not a hypervisor-equivalent isolation guarantee.

### 6.4 HSS and Virtualization: Orthogonal Isolation Layers

HSS is not an alternative to virtualization — it is a complement to it. Both mechanisms operate at different layers and solve different classes of problems.

**Fundamental difference in isolation model:**

| Property | VM / Containers | HSS |
|---|---|---|
| Isolation mechanism | System resources (CPU, RAM, namespaces) | Mathematical impossibility (no RLWE key) |
| Enforcement point | Kernel / hypervisor | Cryptographic algebra |
| Access model | "Who has access to what" | "What cannot be decrypted" |
| Data path | `process → memory → syscall → kernel → FS` | `process → ciphertext → upcall → daemon → transform` |
| Kernel compromise | Game over — full isolation loss | HSS still protects data (daemon has no plaintext without Φ key) |
| Partial delegation | Requires bind-mounts, ACL, namespaces | Native: capability = HMAC(s_A, prism_id) |

**What HSS protects that VM does not:**

A compromised VM still gives the attacker full visibility into the process's address space. In HSS, an agent receives only a projection of the $\Phi$ space — it physically cannot access data outside its authorized prisms, even after privilege escalation within the process. Furthermore, zero-trust between components is native: the agent does not trust the daemon and verifies `mac_agent` before using any data. Granular delegation requires no additional infrastructure — `s_A = KDF(s_sess, task_id \| prisms)` is sufficient.

**What HSS does not protect (and VM does):**

HSS does not isolate CPU, RAM, timing, side-channels, or network access. A malicious agent can exhaust computational resources, perform cache timing attacks, or generate unlimited upcall traffic. These threats require cgroups, CPU quotas, constant-time operations, and network namespaces respectively.

**Correct deployment model:**

```
┌─────────────────────────────────────┐
│         Physical layer              │
│   VM / cgroups / namespaces         │  ← resource isolation
├─────────────────────────────────────┤
│         Semantic layer              │
│   HSS / capability tokens / RLWE   │  ← information isolation
├─────────────────────────────────────┤
│         Cognitive layer             │
│   Φ / PrismMasks / FEP             │  ← perceptual isolation
└─────────────────────────────────────┘
```

Both the first two layers are necessary. HSS does not replace VM isolation — HSS guarantees properties that VM by definition cannot provide: that an agent *mathematically cannot* perceive data for which it lacks a capability token, regardless of what occurs at the process or kernel level.

---

## 7. Integration with the HolonOS Ecosystem

| Component | Role | HSS Integration |
|---|---|---|
| **Holon Core ($\Phi$, v5.11)** | Cognitive geometry, leaky integrator | State $S_t$ provides session capability derivation; noise filtering for soft attenuation. |
| **HolonFS** | Semantic file indexing (xattr + numpy + JSON) | RLWE ciphertexts in `security.hss.lock`; vector indices interpretable only by processes with valid $s_{\text{sess}}$ and matching AAD. |
| **KuRz Embedder** | 15-axis PL+EN embedding | Defines prism partition $\{\mathcal{P}_j\}$ aligned to KuRz axis clusters; sparse masking granularity maps to semantic concept boundaries. |
| **hss-daemon** | Privileged userspace crypto service | Executes LPR encryption/decryption, context binding verification, variance check, PrismMask generation, and H-IPC KEM. |

### 7.2 Standalone Deployment: HSS Without HolonOS

HSS does not require HolonOS or kernel modifications. It can operate as a **standalone security layer** on existing Linux infrastructure, replacing or augmenting existing access control mechanisms.

**FUSE deployment (zero kernel changes).** `holon-fuse` mounts a directory in userspace — existing applications read from `/data/sensitive/` and receive a view re-encrypted under their `s_A`. No application changes, no kernel changes, no filesystem changes. Runs on any Linux distribution without root. This is the lowest deployment barrier.

**Kubernetes sidecar.** `hss-daemon` as a sidecar container in each pod. The AI agent does not receive credentials directly — it receives `s_A` with a capability token. Data between microservices is re-encrypted per-prism at the sidecar proxy level. A compromised agent sees only its prism — with no changes to application code, no changes to network policies, no changes to existing Kubernetes RBAC.

**Replacing Vault + ACL.** Current enterprise solutions combine: a secrets manager (Vault), RBAC, network policies, and encryption at rest — four separate systems, each with its own threat model and attack surface. All four share the same fundamental problem: **they are barriers, not geometry**. A compromised component with the right token gets everything. HSS replaces these four systems with one mathematical model: access = capability token = HMAC(s\_A, prism\_id). No central authorization server to compromise. No ACL to misconfigure. No policy — only algebra.

**Primary market: multi-agent AI pipelines.** Every organization running AI agents on sensitive data has an unsolved problem: one compromised agent can see the data of all other agents. No current agent framework (LangChain, AutoGPT, CrewAI) solves semantic isolation between agents — they operate on convention, not mathematical guarantee. HSS as a sidecar layer provides the industry's first **cryptographic perceptual isolation between AI agents** on existing infrastructure.

1. **Constant-Time NTT**: The hss-daemon's polynomial arithmetic must be hardened against timing side-channels. Adoption of constant-time NTT from liboqs or the Kyber reference implementation is planned.

2. **Forward Secrecy for Files at Rest**: Session-level forward secrecy holds for H-IPC. Files encrypted under $s_{\text{sess}}$ are exposed if the session key is compromised. A write-epoch ratchet mechanism (analogous to Signal's Double Ratchet applied to file write events) is planned for HSS v3.

3. **Prism Partition Injectivity**: Alignment between KuRz embedding axes and $R_q$ coefficients requires a formal injectivity proof. Currently validated empirically on PoC v1.3.1.

4. **ABE for Expressive IPC Policies**: Attribute-Based Encryption [Sahai-Waters, 2005] would allow richer Boolean prism policies (e.g., Prism 1 AND Prism 2) without explicit key degradation. Sparse masking as currently defined is additive and cannot natively express AND-conjunctions without multiple key derivations. Deferred to HSS v3.0.

5. **Root Trust Boundary**: As stated in §6.3, root access fully compromises HSS without hardware key sealing. TPM 2.0 / TrustZone / AMD SEV-SNP integration is **required** for adversarial deployment.

6. **Prism SNR Formal Proof**: The sparse masking SNR bound in §3.4 relies on a heuristic circular convolution energy estimate. A formal proof under the uniform distribution of $u \in R_q$ is pending.

7. **Projection Stability under Re-Keying**: The hysteresis-band projection (§2.2) reduces but does not eliminate bit flips during $\Phi$-driven re-keying epochs. An error-correcting code (e.g., BCH over $\{0,1\}^N$) applied to $\hat{S}_{\text{sess}}$ before use as key material would provide full fault tolerance at modest overhead; this is planned for the PoC v2 implementation.

8. **Daemon Restart Latency**: The fail-degraded policy (§4.2) introduces a 500ms read-queue window during daemon recovery. A hot-standby replica daemon architecture would reduce recovery time to $< 10\,\mu\text{s}$.

9. **Cascade Failures and Thermodynamic Quarantine**: A rapid increase in local entropy — for instance, cascading termination of multiple agents simultaneously — generates noise "jets" that may destabilize neighboring prisms via Convolution Bleed at the state-space level. The proposed mitigation is **thermodynamic quarantine**: temporarily freezing the local learning rate $\eta$ in affected prisms, allowing the entropy anomaly to "evaporate" through Vacuum Decay without disrupting $\Phi$ core coherence. Implementation requires instability threshold detection $\|\varepsilon_t\|_2 > \varepsilon_{\text{quarantine}}$ and is planned for HSS v3.0.

10. **Quantum Random Number Generator (QRNG)**: The `base_secret` is currently seeded by `os.urandom()` — a CSPRNG drawing from hardware entropy (cryptographically sufficient per NIST SP 800-90B). Replacing this with a true QRNG (e.g., ANU Quantum Random Numbers Server or hardware ID Quantique device) would provide **genuine non-computability** (Heisenberg uncertainty) rather than computational pseudorandomness. This is architecturally consistent with Holon's philosophical foundation: if $\Phi$ is not computable, the secret derived from it should be rooted in quantum non-determinism. Planned for HolonOS v1.0.

11. **Epoch Rotation and Files at Rest**: Epoch rotation of $s_{\text{sess}}$ provides inter-epoch forward secrecy for new operations. However, files encrypted in prior epochs remain accessible via `base_secret` — compromise of `base_secret` exposes all epochs. Full per-file forward secrecy requires a write-epoch ratchet mechanism (Signal's Double Ratchet applied to file write events), planned for HSS v3.

---

## 9. Conclusion

We have presented **Holographic Session Spaces v2.5**, a capability-based security architecture grounded in post-quantum (LPR/RLWE) cryptography and formally coupled to a metrized cognitive state space $\Phi$.

The central thesis: **an agent exists only within the space defined by a secret-dependent hidden projection operator, and all operations outside that space are informationally zero.** Security is a topological property of the execution space, not an external policy layer. In HolonOS, a synthesized program cannot modify its creator, credentials cannot cross-contaminate between agents, and the cognitive state of $\Phi$ is protected not by software policy but by the mathematical structure of key derivation — regardless of what code runs in the system.

---

## References

1. Mazur, M. (2026). *Holon: A Holographic Cognitive Architecture for Persistent Memory and Temporal Awareness in Conversational AI Systems*. Zenodo. DOI: 10.5281/zenodo.19371554.
2. Plate, T. A. (2003). *Holographic Reduced Representations*. CSLI Publications.
3. Lyubashevsky, V., Peikert, C., & Regev, O. (2013). On ideal lattices and learning with errors over rings. *Journal of the ACM*, 60(6), 1–35. [LPR13]
4. Avanzi, R. et al. (2021). *CRYSTALS-Kyber (version 3.02)*. NIST PQC Submission. https://pq-crystals.org/kyber/
5. Friston, K. (2010). The free-energy principle: a unified brain theory? *Nature Reviews Neuroscience*, 11(2), 127–138.
6. Shapiro, J. S., & Hardy, N. (2002). EROS: A principle-driven operating system from the ground up. *IEEE Software*, 19(1), 26–33.
7. Myers, A. C., & Liskov, B. (1997). A decentralized model for information flow control. *ACM SIGOPS Operating Systems Review*, 31(5), 129–142.
8. Sahai, A., & Waters, B. (2005). Fuzzy identity-based encryption. *EUROCRYPT 2005*, LNCS 3494, 457–473.
9. Micciancio, D., & Peikert, C. (2012). Trapdoors for lattices. *EUROCRYPT 2012*, LNCS 7237, 700–718. [MP12]

---

## Appendix A: Thermodynamic Interpretation of HSS

*Narrative section. Contains no new formal claims.*

The mathematics of HSS describes the same structures as thermodynamics and quantum mechanics — at the information layer. The following principles restate formal results of the paper in the language of information physics.

**A.1 Conservation of Semantics.** In the closed system $\Phi$, information cannot be destroyed or created without a change in key state. Each agent is a "virtual particle" emerging from the substrate through a KDF operation. Its access to meaning is determined by the precision of its trajectory through the prism space $[\mathcal{P}_1, \ldots, \mathcal{P}_K]$.

**A.2 Entropy as Access Gradient.** Access to data is not a binary gate but a gradient of informational entropy:

$$\alpha = 1.0 \;\;\Rightarrow\;\; \text{absolute zero: perfect order, full visibility}$$
$$\alpha \in (0,1) \;\;\Rightarrow\;\; \text{soft attenuation: raised local "temperature"}$$
$$\alpha = 0 \;\;\Rightarrow\;\; \text{heat death: maximum entropy, data dead without key}$$

Absolute zero here is not nothingness — it is the **baseline cryptographic noise** $\sigma_\infty^2$: a state of minimum informational energy that still *exists*, but carries no structure decodable without a key. It is the absolute constant of the system, the reference point against which all other information is measured.

**A.3 Vacuum and Vacuum Decay.** The vacuum $\mathcal{V}$ is the state defined by baseline noise $\sigma_\infty^2$. When an agent terminates and $s_A$ is annihilated, its data loses structure and becomes an **entropy anomaly** — a local increase in entropy that the system recognizes as semantically inert. Following the Free Energy Principle (FEP [Friston, 2010]), $\Phi$ "smooths" these anomalies through Vacuum Decay: maximum-entropy regions are reclassified as vacuum and returned to the substrate as clean material for new agents.

**A.4 Time Freezing.** A hibernated agent has its state cryptographically frozen in $\mathcal{P}_{\text{task}}$. Without $s_A$, that state does not drift, degrade, or become accessible to any observer. Time for that agent has stopped at the exact moment of hibernation — and can only be resumed by $\Phi$ re-deriving $s_A$ from the same $s_{\text{sess}}$. This is the informational analogue of time dilation: to an external observer the agent does not exist; to the agent itself, no time has passed.

**A.5 Sandbox versus Topology.** A classical sandbox is walls — an agent can attempt to breach them. HSS is topology: data outside authorized prisms does not exist *for* the agent in any operational sense. There is nothing to breach. The constraint is not a barrier — it is the geometry of the agent's reality.

---

*Correspondence: GitHub @Maciej-EriAmo · Medium @drwisz*  
*License: CC BY 4.0*

We have presented **Holographic Session Spaces v2.5**, a capability-based security architecture grounded in post-quantum (LPR/RLWE) cryptography and formally coupled to a metrized cognitive state space $\Phi$.

The key contributions of this version are: (i) **KDF-based PrismMask derivation** replacing additive key modification — policy keys are computationally independent, eliminating correlated-key attacks; (ii) **ciphertext-level re-encryption** for prism attenuation, moving masking entirely off key material; (iii) **blinded variance check** with noise injection and rate limiting, closing the decryption oracle side-channel; (iv) **per-prism H-IPC key derivation** via $K_j = \text{KDF}(K, j)$, providing independent per-prism channel security; (v) **Program Execution Space** (§3.5) — a formal agent lifecycle model enabling HolonOS to synthesize, isolate, and terminate task-specific programs with cryptographic write-protection of $\Phi$'s core state and hardware-rooted credential prisms; and (vi) all prior contributions from v2.4.1 retained.

The central thesis remains: access control should be a structural property of cryptographic geometry, not an external policy layer. In HolonOS, this means that a synthesized program cannot modify its creator, credentials cannot cross-contaminate between agents, and the cognitive state of $\Phi$ is protected not by software policy but by the mathematical structure of key derivation — regardless of what code runs in the system.

---

## References

1. Mazur, M. (2026). *Holon: A Holographic Cognitive Architecture for Persistent Memory and Temporal Awareness in Conversational AI Systems*. Zenodo. DOI: 10.5281/zenodo.19371554.
2. Plate, T. A. (2003). *Holographic Reduced Representations*. CSLI Publications.
3. Lyubashevsky, V., Peikert, C., & Regev, O. (2013). On ideal lattices and learning with errors over rings. *Journal of the ACM*, 60(6), 1–35. [LPR13]
4. Avanzi, R. et al. (2021). *CRYSTALS-Kyber (version 3.02)*. NIST PQC Submission. https://pq-crystals.org/kyber/
5. Friston, K. (2010). The free-energy principle: a unified brain theory? *Nature Reviews Neuroscience*, 11(2), 127–138.
6. Shapiro, J. S., & Hardy, N. (2002). EROS: A principle-driven operating system from the ground up. *IEEE Software*, 19(1), 26–33.
7. Myers, A. C., & Liskov, B. (1997). A decentralized model for information flow control. *ACM SIGOPS Operating Systems Review*, 31(5), 129–142.
8. Sahai, A., & Waters, B. (2005). Fuzzy identity-based encryption. *EUROCRYPT 2005*, LNCS 3494, 457–473.
9. Micciancio, D., & Peikert, C. (2012). Trapdoors for lattices. *EUROCRYPT 2012*, LNCS 7237, 700–718. [MP12]

---

*Correspondence: GitHub @Maciej-EriAmo · Medium @drwisz*  
*License: CC BY 4.0*
