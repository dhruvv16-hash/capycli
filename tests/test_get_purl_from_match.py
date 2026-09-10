from capycli.bom.map_bom import MapBom


def test_get_purl_from_match_stringified_array():
    mb = MapBom()
    # Mocking match with a JSON array string
    match = {"RepositoryId": '["pkg:cargo/clap_builder@4.5.60","pkg:cargo/clap@4.5.60"]'}
    purl = mb.get_purl_from_match(match)
    assert purl == "pkg:cargo/clap_builder@4.5.60"


def test_get_purl_from_match_single_purl():
    mb = MapBom()
    match = {"RepositoryId": "pkg:cargo/clap@4.5.60"}
    purl = mb.get_purl_from_match(match)
    assert purl == "pkg:cargo/clap@4.5.60"
