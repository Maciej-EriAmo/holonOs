# holon_item.py
import time
import numpy as np
from dataclasses import dataclass, field

@dataclass
class Item:
    id:            str
    content:       str
    embedding:     list
    age:           int   = 0
    recalled:      bool  = False
    relevance:     float = 1.0
    created_at:    float = field(default_factory=time.time)
    is_insight:    bool  = False
    insight_level: int   = -1
    cluster_size:  int   = 1
    is_reminder:   bool  = False
    is_fact:       bool  = False
    is_work:       bool  = False
    _norm:         float = field(default=-1.0, repr=False)

    def emb_np(self): return np.array(self.embedding, dtype=np.float32)
    def emb_content(self, cdim=256): return np.array(self.embedding[:cdim], dtype=np.float32)
    def emb_time(self, cdim=256): return np.array(self.embedding[cdim:], dtype=np.float32)
    def norm(self):
        if self._norm < 0: self._norm = float(np.linalg.norm(self.embedding))
        return self._norm
