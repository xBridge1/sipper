LOSS_TARGET_PERCENT = 0.10
LOSS_HIGH_QUALITY_PERCENT = 1.0
LOSS_SEVERE_PERCENT = 5.0
JITTER_IDEAL_MS = 5.0
JITTER_HIGH_QUALITY_MS = 30.0
JITTER_SEVERE_MS = 100.0


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
