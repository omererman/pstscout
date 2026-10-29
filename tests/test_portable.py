
import pytest

from pstscout.portable import (
    UnsafeVaultPath,
    application_root,
    check_volume_access,
    normalize_relative_path,
    resolve_vault_path,
    store_vault_path,
)


def test_application_root_is_based_on_launcher_location(tmp_path):
    assert application_root(tmp_path / "PSTScout.exe") == tmp_path.resolve()


def test_path_reference_survives_drive_root_move(tmp_path):
    first = tmp_path / "USB_E"
    second = tmp_path / "USB_F"
    (first / "vault" / "objects").mkdir(parents=True)
    (second / "vault" / "objects").mkdir(parents=True)
    relative = "vault/objects/af3100.pstsc"
    assert resolve_vault_path(first, relative) == first / relative
    assert resolve_vault_path(second, relative) == second / relative
    assert store_vault_path(first, first / relative) == relative


def test_windows_separators_normalized():
    assert normalize_relative_path(r"vault\objects\abc.pstsc") == "vault/objects/abc.pstsc"


@pytest.mark.parametrize(
    "bad",
    [
        "", "../secrets", "objects/../secrets", "objects//x", "objects/./x",
        r"C:\secrets.pst", r"C:secrets.pst", r"\\server\share\secrets",
        "/etc/passwd", "objects/x:stream", "objects/\x00bad",
    ],
)
def test_bad_paths_rejected(tmp_path, bad):
    with pytest.raises(UnsafeVaultPath):
        resolve_vault_path(tmp_path, bad)


def test_non_string_rejected():
    with pytest.raises(TypeError):
        normalize_relative_path(None)


def test_path_outside_vault_rejected(tmp_path):
    inside = tmp_path / "vault"
    inside.mkdir()
    with pytest.raises(UnsafeVaultPath):
        store_vault_path(inside, tmp_path / "outside.pstsc")


def test_symlink_outside_vault_rejected(tmp_path):
    vault = tmp_path / "vault"
    outside = tmp_path / "outside"
    vault.mkdir()
    outside.mkdir()
    link = vault / "external"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink requires permission on this Windows host")
    with pytest.raises(UnsafeVaultPath):
        resolve_vault_path(vault, "external/file.pstsc")


def test_usb_probe_success_and_cleanup(tmp_path):
    before = set(tmp_path.iterdir())
    result = check_volume_access(tmp_path)
    assert result.readable and result.writable
    assert set(tmp_path.iterdir()) == before


def test_usb_probe_missing_folder(tmp_path):
    result = check_volume_access(tmp_path / "missing")
    assert not result.readable and not result.writable


def test_doctor_output_does_not_disclose_root_path(tmp_path, capsys):
    from pstscout.cli import main

    assert main(["doctor", "--root", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert str(tmp_path) not in output
    assert "USB readable: YES" in output
    assert "USB writable: YES" in output
