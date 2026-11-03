from __future__ import annotations

import pytest

from canonical_sync.cli import main


def test_refresh_google_drive_adc_subcommand_dispatches_help() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["refresh-google-drive-adc", "--help"])
    assert caught.value.code == 0
