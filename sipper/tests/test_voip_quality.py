from ciper.voip_quality import jitter_observation, packet_loss_observation


def test_packet_loss_observation_uses_voip_quality_ranges():
    assert "excelente" in packet_loss_observation(0.10).lower()
    assert "atencao" in packet_loss_observation(0.50).lower()
    assert "degradada" in packet_loss_observation(2.0).lower()
    assert "critica" in packet_loss_observation(5.0).lower()


def test_jitter_observation_uses_voip_quality_ranges():
    assert "excelente" in jitter_observation(0.002, 0.005).lower()
    assert "aceitavel" in jitter_observation(0.010, 0.030).lower()
    assert "degradado" in jitter_observation(0.030, 0.080).lower()
    assert "critico" in jitter_observation(0.040, 0.101).lower()
