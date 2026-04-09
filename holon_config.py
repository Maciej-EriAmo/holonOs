# holon_config.py
import os
from dataclasses import dataclass, field

@dataclass
class Config:
    k:             int   = 4
    n:             int   = 7
    threshold:     float = 0.20
    lr:            float = 0.01
    alpha:         float = 0.05
    top_n_recall:  int   = 2
    dim:           int   = 256
    time_dim:      int   = 8

    @property
    def total_dim(self) -> int:
        return self.dim + self.time_dim

    phi_half_life_hours: list = field(default_factory=lambda: [
        [ 24.0,  18.0,  12.0,   8.0],
        [168.0, 120.0,  96.0,  72.0],
        [720.0, 540.0, 360.0, 240.0],
    ])
    store_decay_hours:    float = 336.0
    phi_min_norm:         float = 0.1
    phi_ortho_beta:       float = 0.05
    vacuum_age_tau:       float = 50.0
    recall_age_penalty:   float = 0.02
    aii_adapt_range:      float = 0.15
    vacuum_warmup_turns:  int   = 8
    phi_stability_decay:  float = 0.95
    phi_stability_max:    float = 5.0
    coherence_threshold:  float = 0.4
    phi_levels:           int   = 3
    phase_shifts:         list  = field(default_factory=lambda: [0.0, 0.33, 0.66])
    rumination_interval:  int   = 12
    rumination_threshold: float = 0.35
    rumination_shifts:    list  = field(default_factory=lambda: [0.0, 0.25, 0.5, 0.75])
    surprise_adapt_rate:  float = 0.005
    surprise_trigger:     float = 0.4
    lr_min:               float = 0.001
    lr_max:               float = 0.025
    precision_mode:       str   = 'error'
    soft_vacuum_interval: int   = 4
    soft_decay_factor:    float = 0.96
    hard_prune_interval:  int   = 20
    hard_prune_store_max: int   = 120
    focus_boost:          float = 1.25
    phase_shifts_learnable: bool = True
    conversation_history_size: int = 12
    topic_repeat_threshold:    int = 3
    use_prism: bool   = False
    prism_cfg: object = None
    rumination_generate_insight: bool = True
    insight_prompt_template: str = (
        "Jesteś EriAmo. Przeanalizuj swój błąd predykcji w architekturze Holon.\n"
        "Wykryto niespójność czasowo-przestrzenną: {max_inc:.3f}\n"
        "Wygeneruj jeden zwięzły wniosek (insight), czego się z tego nauczyłeś "
        "i jak to wpływa na Twój model otoczenia:\n"
    )
