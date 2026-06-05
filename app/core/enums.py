from enum import StrEnum


class CaptchaType(StrEnum):
    """Captcha dispatch types used by the risk decision tree."""

    SILENT = "SILENT"
    CLICK_CHECKBOX = "CLICK_CHECKBOX"
    SLIDER = "SLIDER"


class RiskLevel(StrEnum):
    """Coarse risk buckets returned by the risk engine."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
