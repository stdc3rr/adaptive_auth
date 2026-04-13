"""Централизованные константы адаптивной аутентификации для формул и решений."""

# Веса формул (в каждой группе сумма должна быть 1.0)
ALPHA_GEO = 0.6

GAMMA_IP = 0.35
GAMMA_PROVIDER = 0.20
GAMMA_VPN = 0.25
GAMMA_REPUTATION = 0.20

DELTA_TRIES = 0.35
DELTA_SPEED = 0.25
DELTA_DELAY = 0.20
DELTA_REPEAT = 0.20

W_GT = 0.25
W_DEV = 0.25
W_NET = 0.30
W_SESS = 0.20

# Пороговые значения решений
RISK_LOW_MAX = 0.39
RISK_MEDIUM_MAX = 0.69

# Защита от перебора паролей
MAX_FAILED_ATTEMPTS_PER_15_MIN = 5
SOFT_LOCK_MINUTES = 10

# Параметры MFA
MFA_CODE_TTL_MINUTES = 5
