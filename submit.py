import sys
import subprocess
import zipfile
from pathlib import Path

# Files to include in the submission zip (base names will be stored, similar to `zip -j`).
FILES = [
    "foggytcp/src/foggy_function.cc",
    "foggytcp/src/foggy_tcp.cc",
    "foggytcp/inc/foggy_function.h",
    "foggytcp/inc/foggy_tcp.h",
]


def get_git_short_hash():
    """Return the short git commit hash, or None if git isn't available."""
    try:
        out = subprocess.check_output(["git", "log", "-1", "--pretty=format:%h"], stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return None


def write_cur_commit(hash_str: str, git_dir: str = ".git") -> Path:
    """Write CUR_COMMIT file under .git (create .git if missing). Returns the Path to the file."""
    git_path = Path(git_dir)
    git_path.mkdir(parents=True, exist_ok=True)
    cur_file = git_path / "CUR_COMMIT"
    cur_file.write_text(hash_str or "")
    return cur_file


def create_zip(zip_name: str, files: list, cur_commit_file: Path) -> tuple:
    """Create a zip file containing the CUR_COMMIT and the requested files.

    Returns (zip_path: Path, missing_files: list).
    """
    zip_path = Path(zip_name)
    missing = []
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # add CUR_COMMIT (store only the filename)
        if cur_commit_file and cur_commit_file.exists():
            zf.write(cur_commit_file, arcname=cur_commit_file.name)
        else:
            # create empty CUR_COMMIT entry if file is absent
            zf.writestr("CUR_COMMIT", "")

        for f in files:
            p = Path(f)
            if p.exists():
                # store using only the base filename to mimic `-j`
                zf.write(p, arcname=p.name)
            else:
                missing.append(f)

    return zip_path, missing


def main():
    git_hash = get_git_short_hash()
    if git_hash:
        print(f"Git commit: {git_hash}")
    else:
        print("Warning: could not get git commit hash (git missing or not a repo). Writing empty CUR_COMMIT.")

    cur_file = write_cur_commit(git_hash or "")
    zip_path, missing = create_zip("submit.zip", FILES, cur_file)

    print(f"Created: {zip_path.resolve()}")
    if missing:
        print("Warning: the following files were missing and not added to the zip:")
        for m in missing:
            print(" -", m)
        # non-zero exit code to indicate a partial submission
        sys.exit(2)

    print("All files added to submit.zip.")
    sys.exit(0)


if __name__ == "__main__":
    main()
