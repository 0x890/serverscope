"""Local statistical / ML toolbox. Pure-Python fallbacks; sklearn optional.

No external AI APIs — everything runs locally.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return ordered[int(k)]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def moving_average(values: list[float], window: int) -> list[float]:
    if window <= 0 or not values:
        return []
    out: list[float] = []
    acc = 0.0
    for i, v in enumerate(values):
        acc += v
        if i >= window:
            acc -= values[i - window]
        out.append(acc / min(i + 1, window))
    return out


def ewma(values: list[float], alpha: float = 0.3) -> list[float]:
    out: list[float] = []
    current: float | None = None
    for v in values:
        current = v if current is None else alpha * v + (1 - alpha) * current
        out.append(current)
    return out


def linear_trend(values: list[float]) -> float:
    """Least-squares slope per sample. Positive = growing."""
    n = len(values)
    if n < 2:
        return 0.0
    mean_x = (n - 1) / 2.0
    mean_y = sum(values) / n
    num = sum((i - mean_x) * (v - mean_y) for i, v in enumerate(values))
    den = sum((i - mean_x) ** 2 for i in range(n))
    return num / den if den else 0.0


def forecast_linear(values: list[float], steps: int) -> list[float]:
    slope = linear_trend(values)
    last = values[-1] if values else 0.0
    return [last + slope * (i + 1) for i in range(steps)]


def zscore_anomalies(values: list[float], threshold: float = 3.0) -> list[int]:
    """Indices of points more than `threshold` standard deviations from the mean."""
    if len(values) < 4:
        return []
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values)
    if stdev == 0:
        return []
    return [i for i, v in enumerate(values) if abs(v - mean) / stdev > threshold]


@dataclass
class SeasonalDecomposition:
    trend: list[float]
    seasonal: list[float]
    residual: list[float]


def seasonal_decompose(values: list[float], period: int) -> SeasonalDecomposition | None:
    """Additive decomposition: centered MA trend + mean-by-phase seasonality."""
    if period < 2 or len(values) < 2 * period:
        return None
    trend = moving_average(values, period)
    detrended = [v - t for v, t in zip(values, trend)]
    phase_means: list[float] = []
    for phase in range(period):
        phase_vals = detrended[phase::period]
        phase_means.append(statistics.fmean(phase_vals) if phase_vals else 0.0)
    seasonal = [phase_means[i % period] for i in range(len(values))]
    residual = [d - s for d, s in zip(detrended, seasonal)]
    return SeasonalDecomposition(trend=trend, seasonal=seasonal, residual=residual)


class BehaviorBaseline:
    """Per-host baseline: flags values outside the learned normal band."""

    def __init__(self, history: list[float]) -> None:
        self._mean = statistics.fmean(history) if history else 0.0
        self._stdev = statistics.pstdev(history) if len(history) > 1 else 0.0

    def is_anomalous(self, value: float, sigmas: float = 3.0) -> bool:
        if self._stdev == 0:
            return abs(value - self._mean) > max(1.0, abs(self._mean))
        return abs(value - self._mean) / self._stdev > sigmas


# ── sklearn-backed multivariate models (optional) ──────────────────────────

def isolation_forest_scores(matrix: list[list[float]]) -> list[float] | None:
    """Anomaly scores in [0,1] (higher = more anomalous). None if sklearn absent."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return _fallback_outlier_scores(matrix)
    if len(matrix) < 8:
        return _fallback_outlier_scores(matrix)
    model = IsolationForest(random_state=42, contamination="auto")
    model.fit(matrix)
    raw = model.score_samples(matrix)  # more negative = more anomalous
    lo, hi = min(raw), max(raw)
    span = (hi - lo) or 1.0
    return [1.0 - (r - lo) / span for r in raw]


def dbscan_labels(matrix: list[list[float]], eps: float = 0.5, min_samples: int = 3) -> list[int] | None:
    try:
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return None
    if len(matrix) < min_samples:
        return None
    scaled = StandardScaler().fit_transform(matrix)
    return list(DBSCAN(eps=eps, min_samples=min_samples).fit_predict(scaled))


def kmeans_labels(matrix: list[list[float]], k: int = 3) -> list[int] | None:
    try:
        from sklearn.cluster import KMeans
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return None
    if len(matrix) < k:
        return None
    scaled = StandardScaler().fit_transform(matrix)
    return list(KMeans(n_clusters=k, random_state=42, n_init=10).fit_predict(scaled))


def _fallback_outlier_scores(matrix: list[list[float]]) -> list[float] | None:
    """Mean per-dimension |z-score|, squashed to [0,1]."""
    if not matrix:
        return None
    dims = len(matrix[0])
    n = len(matrix)
    means = [statistics.fmean(row[d] for row in matrix) for d in range(dims)]
    stdevs = [statistics.pstdev([row[d] for row in matrix]) or 1.0 for d in range(dims)]
    scores: list[float] = []
    for row in matrix:
        z = sum(abs(row[d] - means[d]) / stdevs[d] for d in range(dims)) / dims
        scores.append(min(1.0, z / 4.0))
    return scores if n > 1 else [0.0]
