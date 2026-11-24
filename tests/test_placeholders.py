import graph
import reporter
import cli


def test_graph_module_imports():
    assert graph is not None


def test_reporter_module_imports():
    assert reporter is not None


def test_cli_module_imports():
    assert cli is not None
