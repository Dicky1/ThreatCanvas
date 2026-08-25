from app.schemas.cti import CTIFetchRequest
from app.services.cti_connectors import CTIConnectorService


def test_cti_connector_normalizes_misp_payload():
    result = CTIConnectorService().fetch(
        CTIFetchRequest(
            source_type="misp",
            payload={
                "Event": {
                    "Attribute": [
                        {"type": "text", "value": "Observed T1059.001 execution"},
                        {"type": "domain", "value": "evil.example"},
                    ]
                }
            },
        )
    )

    assert result.source_type == "misp"
    assert result.techniques == ["T1059.001"]
    assert result.indicator_count == 2


def test_cti_connector_uses_injected_fetcher_for_taxii():
    def fetcher(url, token):
        assert url == "https://taxii.example/collections/1/objects"
        assert token == "secret"
        return {"objects": [{"type": "attack-pattern", "name": "T1486"}]}

    result = CTIConnectorService(fetcher=fetcher).fetch(
        CTIFetchRequest(
            source_type="taxii",
            url="https://taxii.example/collections/1/objects",
            token="secret",
        )
    )

    assert result.techniques == ["T1486"]
