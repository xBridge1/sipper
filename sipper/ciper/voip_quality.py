LOSS_TARGET_PERCENT = 0.10
LOSS_HIGH_QUALITY_PERCENT = 1.0
LOSS_SEVERE_PERCENT = 5.0
JITTER_IDEAL_MS = 5.0
JITTER_HIGH_QUALITY_MS = 30.0
JITTER_SEVERE_MS = 100.0


def estimate_mos(loss_percent, jitter_seconds, codec=None):
    jitter_ms = max(0.0, jitter_seconds * 1000)
    codec_penalty = 7.0 if codec in {"G729", "G723"} else 0.0
    loss_penalty = min(70.0, max(0.0, loss_percent) * 2.5)
    jitter_penalty = min(35.0, max(0.0, jitter_ms - 20.0) * 0.35)
    rating = max(0.0, min(100.0, 93.2 - codec_penalty - loss_penalty - jitter_penalty))
    mos = 1.0 + 0.035 * rating + rating * (rating - 60.0) * (100.0 - rating) * 0.000007
    return round(max(1.0, min(4.5, mos)), 2)


def mos_observation(mos):
    if mos >= 4.0:
        state = "boa"
    elif mos >= 3.5:
        state = "aceitavel"
    elif mos >= 3.0:
        state = "degradada"
    else:
        state = "ruim"

    return f"MOS estimado: {mos:.2f} ({state}). Estimativa baseada em perda e variacao RTP; atraso fim a fim nao foi medido."


def packet_loss_observation(loss_percent):
    if loss_percent <= LOSS_TARGET_PERCENT:
        state = "Excelente"
    elif loss_percent < LOSS_HIGH_QUALITY_PERCENT:
        state = "Atencao"
    elif loss_percent < LOSS_SEVERE_PERCENT:
        state = "Degradada"
    else:
        state = "Critica"

    return (
        f"Perda {state.lower()}: {loss_percent:.2f}%. Alvo operacional: ate "
        f"{LOSS_TARGET_PERCENT:.2f}%; voz de alta qualidade: abaixo de "
        f"{LOSS_HIGH_QUALITY_PERCENT:.0f}%; critica: {LOSS_SEVERE_PERCENT:.0f}% ou mais."
    )


def jitter_observation(average_seconds, maximum_seconds):
    average_ms = average_seconds * 1000
    maximum_ms = maximum_seconds * 1000

    if maximum_ms <= JITTER_IDEAL_MS:
        state = "Excelente"
    elif maximum_ms <= JITTER_HIGH_QUALITY_MS:
        state = "Aceitavel"
    elif maximum_ms <= JITTER_SEVERE_MS:
        state = "Degradado"
    else:
        state = "Critico"

    return (
        f"Jitter {state.lower()}: medio {average_ms:.1f} ms, maximo {maximum_ms:.1f} ms. "
        f"Ideal: ate {JITTER_IDEAL_MS:.0f} ms; voz de alta qualidade: ate "
        f"{JITTER_HIGH_QUALITY_MS:.0f} ms; critico: acima de {JITTER_SEVERE_MS:.0f} ms."
    )


def quality_reference_note():
    return (
        "Referencia VoIP: perda abaixo de 1% e jitter abaixo de 30 ms favorecem alta "
        "qualidade. Buffer de jitter e codec podem alterar o impacto percebido."
    )
