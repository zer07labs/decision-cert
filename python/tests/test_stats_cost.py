"""Bounded-loss statistics for the v1.4 draft's `selective_cost` (spec/drafts/cost-weighted-abstention.md §1):
the Hoeffding-Bentkus p-value and bound, and Learn-then-Test on mean normalised loss."""

from __future__ import annotations

import math

import numpy as np
import pytest
from scipy.stats import binom

from decision_cert.issue import stats as cs


def test_zero_loss_gives_the_one_sided_hoeffding_term() -> None:
    for n in (1, 10, 45, 500):
        assert cs.hb_p_value(n, 0.0, 0.05) == pytest.approx((1 - 0.05) ** n, rel=1e-12)
    assert cs.hb_p_value(0, 0.0, 0.05) == 1.0


def test_the_p_value_is_one_at_or_above_alpha() -> None:
    assert cs.hb_p_value(100, 5.0, 0.05) == 1.0
    assert cs.hb_p_value(100, 30.0, 0.05) == 1.0


def test_the_vectorised_p_values_match_the_scalar_ones() -> None:
    rng = np.random.default_rng(7)
    n = rng.integers(0, 3000, 500)
    s = rng.random(500) * n * 0.2
    got = cs.hb_p_values(n, s, 0.1)
    want = np.array([cs.hb_p_value(int(a), float(b), 0.1) for a, b in zip(n, s, strict=True)])
    np.testing.assert_allclose(got, want, rtol=1e-12, atol=0)


def test_on_zero_one_losses_hb_is_never_below_the_exact_binomial() -> None:
    # the Chernoff term bounds the binomial cdf from above, and e·cdf ≥ cdf: HB is the more conservative test
    for n in (20, 100, 1000):
        for e in range(0, n // 5):
            for alpha in (0.05, 0.1, 0.2):
                assert cs.hb_p_value(n, float(e), alpha) >= cs.p_value(n, e, alpha) * (1 - 1e-12)


def test_float_noise_in_the_loss_sum_does_not_move_the_ceiling() -> None:
    noisy = sum([0.1] * 20)  # 2.0000000000000004
    assert noisy != 2.0
    assert cs.hb_p_value(200, noisy, 0.05) == cs.hb_p_value(200, 2.0, 0.05)
    assert math.ceil(2.5 - 1e-9) == 3  # a real fractional part still rounds up


def test_the_bentkus_term_matters_for_small_losses() -> None:
    n, s, alpha = 300, 6.0, 0.05
    hoeffding = math.exp(-n * cs._kl(s / n, alpha))
    bentkus = math.e * float(binom.cdf(6, n, alpha))
    assert cs.hb_p_value(n, s, alpha) == pytest.approx(min(hoeffding, bentkus))


@pytest.mark.parametrize(("n", "s"), [(50, 0.0), (200, 3.5), (1000, 41.25), (10, 9.0)])
def test_the_ucb_is_where_the_p_value_crosses_delta(n: int, s: float) -> None:
    delta = 0.1
    u = cs.hb_ucb(n, s, delta)
    assert s / n <= u <= 1.0
    if u < 1.0:
        assert cs.hb_p_value(n, s, u) <= delta
        assert cs.hb_p_value(n, s, u - 1e-9) > delta
    assert cs.hb_ucb(0, 0.0, delta) == 1.0


def test_the_hb_ucb_is_never_tighter_than_clopper_pearson_on_zero_one_losses() -> None:
    for n, e in [(50, 0), (200, 4), (1000, 30)]:
        assert cs.hb_ucb(n, float(e), 0.1) >= cs.ucb(n, e, 0.1) - 1e-12


def test_loss_sums_reduce_to_counts_on_zero_one_losses() -> None:
    rng = np.random.default_rng(3)
    conf, err = rng.random(400), rng.random(400) < 0.2
    cuts = cs.cuts_of(conf[:200])
    n1, e1 = cs.counts(conf, err, cuts)
    n2, s2 = cs.loss_sums(conf, err.astype(float), cuts)
    np.testing.assert_array_equal(n1, n2)
    np.testing.assert_array_equal(e1.astype(float), s2)


def test_cost_ltt_on_zero_one_losses_is_never_looser_than_v1_ltt() -> None:
    rng = np.random.default_rng(11)
    for _ in range(50):
        conf = rng.uniform(0.5, 1.0, 600)
        err = rng.random(600) < 0.4 * (1 - conf)
        cuts = cs.cuts_of(conf)
        v1 = cs.ltt(conf, err, cuts, 0.05, 0.1)
        hb = cs.cost_ltt(conf, err.astype(float), cuts, 0.05, 0.1)
        assert hb.abstain_below >= v1.abstain_below


def test_cost_ltt_stops_at_the_first_cut_that_is_not_rejected() -> None:
    conf = np.array([0.99] * 100 + [0.8] * 100)
    loss = np.array([0.0] * 100 + [0.5] * 100)
    pt = cs.cost_ltt(conf, loss, np.array([0.9, 0.5, 0.0]), alpha=0.1, delta=0.1)
    assert (pt.abstain_below, pt.n, pt.loss_sum, pt.coverage) == (0.9, 100, 0.0, 0.5)
    none = cs.cost_ltt(conf, np.ones(200), np.array([0.9, 0.0]), alpha=0.1, delta=0.1)
    assert none.abstain_below == cs.ABSTAIN_ALL and none.n == 0


def test_cheap_errors_certify_more_than_their_error_rate_would() -> None:
    # every error costs a fifth of c_max: the mean loss is a fifth of the error rate
    rng = np.random.default_rng(5)
    conf = rng.uniform(0.5, 1.0, 4000)
    err = rng.random(4000) < 0.6 * (1 - conf)
    cuts = cs.cuts_of(conf[:2000])
    v1 = cs.ltt(conf[2000:], err[2000:], cuts, 0.05, 0.1)
    cheap = cs.cost_ltt(conf[2000:], err[2000:] * 0.2, cuts, 0.05, 0.1)
    assert cheap.coverage > v1.coverage
