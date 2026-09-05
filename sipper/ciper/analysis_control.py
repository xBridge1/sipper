class AnalysisCancelled(Exception):
    pass


def raise_if_cancelled(cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled("Analise cancelada pelo usuario")
