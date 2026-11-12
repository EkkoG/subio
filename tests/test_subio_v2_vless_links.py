import pytest

from subio_v2.adapters.catalog import get_emitter
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.adapters.links.parser import V2RayNParser
from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.workflow.engine import WorkflowEngine

USER_ID = "2cae91b3-f85c-433b-88ee-a002b9ed6d61"
PUBLIC_KEY = "dwrjY6KiAMPxKdlF7T4AWFXXBtsxeHCXtBQYeCOdZV4"
BASE = f"vless://{USER_ID}@example.com:443?"


@pytest.mark.parametrize("target", ["v2rayn", "dae"])
def test_vless_link_grpc_fields_reach_surge_and_link_output(target):
    parsed = V2RayNParser().parse_result(
        BASE
        + "type=grpc&security=tls&mode=multi&authority=edge.example.com&serviceName=%2Fmy%2Fpath%2Ftun%7Ctunmulti&alpn=h2%2Chttp%2F1.1#node"
    )
    assert parsed.issues == []
    node = parsed.nodes[0]
    assert node.transport.grpc_mode == "multi"
    assert node.transport.grpc_authority == "edge.example.com"
    assert node.tls.alpn == ["h2", "http/1.1"]
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    surge = SurgeParser().parse_result(output.content)
    assert surge.issues == []
    assert surge.nodes[0].transport == node.transport
    link_output = get_emitter(target).emit_result(surge.nodes)
    assert link_output.errors == []
    plain = link_output.fragments.plain_list or link_output.fragments.subscription
    assert plain is not None
    again = V2RayNParser().parse_result(plain)
    assert again.issues == []
    assert again.nodes[0].transport == node.transport
    assert again.nodes[0].tls.alpn == node.tls.alpn


@pytest.mark.parametrize(
    "query",
    [
        "security=unknown",
        "security=",
        "security=tls&security=none",
        "type=tcp&type=ws",
        "encryption=mlkem768x25519plus",
        "encryption=",
        "security=tls&pcs=pin",
        "security=tls&vcn=verify.example.com",
        "security=tls&ech=config",
        "security=reality&pqv=public",
        "security=reality&spx=%2F",
        "security=tls&fm=mode",
        "type=grpc&security=tls&mode=unknown",
        "type=tcp&authority=edge.example.com",
        "security=none&pbk=key",
        "security=tls&alpn=",
        "security=tls&allowInsecure=unknown",
    ],
)
def test_unsupported_vless_security_cannot_become_a_weaker_node(query):
    parsed = V2RayNParser().parse_result(BASE + query)
    assert parsed.nodes == []
    assert parsed.issues[0].code == "parse.link"
    assert USER_ID not in parsed.issues[0].message


def test_vless_raw_reality_and_alpn_reach_surge():
    parsed = V2RayNParser().parse_result(
        BASE
        + f"type=raw&security=reality&pbk={PUBLIC_KEY}&sid=0123456789abcdef&flow=xtls-rprx-vision&alpn=h2#node"
    )
    assert parsed.issues == []
    assert parsed.nodes[0].transport.network_value == "tcp"
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    assert "reality-public-key=" in output.content
    assert "alpn=h2" in output.content


@pytest.mark.parametrize("dialect,network", [("mihomo", "ws"), ("stash", "grpc")])
def test_existing_clash_family_vless_inputs_reach_surge(dialect, network):
    parsed = ClashParser(DialectContext(dialect, "yaml")).parse_result(
        {
            "proxies": [
                {
                    "name": "node",
                    "type": "vless",
                    "server": "example.com",
                    "port": 443,
                    "uuid": USER_ID,
                    "tls": True,
                    "network": network,
                    **(
                        {
                            "ws-opts": {
                                "path": "/vless",
                                "headers": {"Host": "edge.example.com"},
                            }
                        }
                        if network == "ws"
                        else {"grpc-opts": {"grpc-service-name": "mygrpc"}}
                    ),
                }
            ]
        }
    )
    assert parsed.issues == []
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    again = SurgeParser().parse_result(output.content).nodes[0].transport
    assert again.network_value == network
    assert again.path == parsed.nodes[0].transport.path
    assert again.headers == parsed.nodes[0].transport.headers
    assert again.grpc_service_name == parsed.nodes[0].transport.grpc_service_name


def test_mihomo_vless_encryption_cannot_be_downgraded_to_surge():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "node",
                    "type": "vless",
                    "server": "example.com",
                    "port": 443,
                    "uuid": USER_ID,
                    "tls": True,
                    "encryption": "mlkem768x25519plus",
                }
            ]
        }
    )
    assert parsed.issues == []
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.supported_nodes == []
    assert any(issue.field == "encryption" for issue in output.errors)


@pytest.mark.parametrize("target", ["v2rayn", "dae"])
def test_surge_certificate_guarantee_cannot_be_dropped_by_link_output(target):
    parsed = SurgeParser().parse_result(
        f"node = vless, example.com, 443, username={USER_ID}, tls=true, server-cert-fingerprint-sha256={'a' * 64}"
    )
    assert parsed.issues == []
    output = get_emitter(target).emit_result(parsed.nodes)
    assert output.supported_nodes == []
    assert any(issue.field == "tls.certificate_sha256" for issue in output.errors)


@pytest.mark.parametrize("invalid", [False, True])
def test_vless_link_workflow_preserves_grpc_or_blocks_publication(
    tmp_path, monkeypatch, invalid
):
    monkeypatch.chdir(tmp_path)
    query = "type=grpc&security=tls&mode=multi&authority=edge.example.com&serviceName=mygrpc&alpn=h2"
    if invalid:
        query += "&pcs=unmodeled-pin"
    (tmp_path / "nodes.txt").write_text(BASE + query + "#node")
    config = tmp_path / "config.toml"
    config.write_text("""
[[provider]]
name = "links"
type = "v2rayn"
file = "nodes.txt"

[[artifact]]
name = "out.conf"
type = "surge"
providers = ["links"]
""")
    engine = WorkflowEngine(str(config), dry_run=True)
    output = tmp_path / "dist/out.conf"
    if invalid:
        with pytest.raises(ArtifactGenerationError) as exc_info:
            engine.run()
        assert any(issue.code == "parse.link" for issue in exc_info.value.issues)
        assert not output.exists()
    else:
        engine.run()
        parsed = SurgeParser().parse_result(output.read_text())
        assert parsed.issues == []
        assert parsed.nodes[0].transport.grpc_mode == "multi"
        assert parsed.nodes[0].transport.grpc_authority == "edge.example.com"
