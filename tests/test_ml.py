from __future__ import annotations

from serverscope.analyzer import ml


def test_percentile() -> None:
    values = [float(i) for i in range(1, 101)]
    assert ml.percentile(values, 95) == 95.05
    assert ml.percentile([], 95) is None


def test_moving_average_converges() -> None:
    out = ml.moving_average([10.0] * 20, window=5)
    assert out[-1] == 10.0


def test_linear_trend_direction() -> None:
    assert ml.linear_trend([1.0, 2.0, 3.0, 4.0]) == 1.0
    assert ml.linear_trend([4.0, 3.0, 2.0, 1.0]) == -1.0
    assert ml.linear_trend([5.0]) == 0.0


def test_forecast_linear() -> None:
    forecast = ml.forecast_linear([1.0, 2.0, 3.0], steps=2)
    assert forecast == [4.0, 5.0]


def test_zscore_anomalies() -> None:
    values = [10.0] * 30 + [500.0]
    assert 30 in ml.zscore_anomalies(values)


def test_seasonal_decompose() -> None:
    values = [10.0, 20.0] * 10  # period-2 seasonality
    result = ml.seasonal_decompose(values, period=2)
    assert result is not None
    assert len(result.seasonal) == 20
    # phases should differ
    assert abs(result.seasonal[0] - result.seasonal[1]) > 1


def test_behavior_baseline() -> None:
    baseline = ml.BehaviorBaseline([10.0, 11.0, 9.0, 10.5, 9.5] * 4)
    assert baseline.is_anomalous(100.0)
    assert not baseline.is_anomalous(10.2)


def test_outlier_scores_fallback() -> None:
    matrix = [[1.0, 1.0]] * 10 + [[100.0, 100.0]]
    scores = ml.isolation_forest_scores(matrix)
    assert scores is not None
    assert scores[-1] == max(scores)
