from threading import Event

import pytest

from ciper.analysis_control import AnalysisCancelled, raise_if_cancelled


def test_raise_if_cancelled_stops_analysis():
    cancel_event = Event()
    cancel_event.set()

    with pytest.raises(AnalysisCancelled):
        raise_if_cancelled(cancel_event)
