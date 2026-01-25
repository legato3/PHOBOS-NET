from app.services.events import rules


def test_rule_new_external_destination():
    event = rules.rule_new_external_destination(
        ts=1700000000,
        dst_ip="8.8.8.8",
        country="US",
        dst_ports=[53],
        top_src_ip="10.0.0.1",
        bytes_count=1024,
        flows_count=10,
    )
    assert event.rule_id == "NEW_EXTERNAL_DESTINATION"
    assert "8.8.8.8" in event.title


def test_rule_top_talker_changed():
    event = rules.rule_top_talker_changed(
        ts=1700000000,
        direction="src",
        old_top="10.0.0.1",
        new_top="10.0.0.2",
        delta_pct=25.0,
        bytes_count=2048,
    )
    assert event.rule_id == "TOP_TALKER_CHANGED"
    assert "Top" in event.title


def test_rule_port_spike():
    event = rules.rule_port_spike(
        ts=1700000000,
        port=443,
        current=300,
        baseline=50,
        top_src="10.0.0.5",
        top_dst="1.2.3.4",
    )
    assert event.rule_id == "PORT_SPIKE"
    assert event.count == 300


def test_rule_block_spike():
    event = rules.rule_block_spike(
        ts=1700000000,
        interface="wan",
        action="block",
        current=200,
        baseline=40,
        top_src="8.8.8.8",
        top_dst="10.0.0.1",
        top_port=22,
    )
    assert event.rule_id == "BLOCK_SPIKE"
    assert event.source == "filterlog"


def test_rule_new_inbound_wan_source():
    event = rules.rule_new_inbound_wan_source(
        ts=1700000000,
        src_ip="5.6.7.8",
        country="GB",
        dst_port=3389,
        rule_label="WAN_IN",
    )
    assert event.rule_id == "NEW_INBOUND_WAN_SOURCE"
    assert event.evidence["dst_port"] == 3389


def test_rule_rule_hit_spike():
    event = rules.rule_rule_hit_spike(
        ts=1700000000,
        rule_id="123",
        rule_label="WAN_RULE",
        current=120,
        baseline=20,
    )
    assert event.rule_id == "RULE_HIT_SPIKE"
    assert event.count == 120


def test_rule_nxdomain_burst():
    event = rules.rule_nxdomain_burst(
        ts=1700000000,
        current=60,
        baseline=10,
        top_domains=["example.com"],
        top_clients=["10.0.0.2"],
    )
    assert event.rule_id == "NXDOMAIN_BURST"
    assert event.source == "syslog"


def test_rule_new_domain_to_many_hosts():
    event = rules.rule_new_domain_to_many_hosts(
        ts=1700000000,
        domain="new.example",
        host_count=5,
        top_hosts=["10.0.0.2", "10.0.0.3"],
    )
    assert event.rule_id == "NEW_DOMAIN_TO_MANY_HOSTS"
    assert event.count == 5


def test_rule_source_stale():
    event = rules.rule_source_stale(
        ts=1700000000,
        source="syslog_514",
        last_seen_age=600,
        threshold=180,
    )
    assert event.rule_id == "SOURCE_STALE"
    assert event.source == "system"


def test_rule_parser_error_spike():
    event = rules.rule_parser_error_spike(
        ts=1700000000,
        parser="syslog_514",
        current=30,
        baseline=5,
        sample_error="parse failure",
    )
    assert event.rule_id == "PARSER_ERROR_SPIKE"
    assert event.severity == "warn"
