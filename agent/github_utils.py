import os
import shutil
import stat
from git import Repo

BASE_DIR = "temp_repos"


def clone_repo(repo_url: str):
    if "github.com" not in repo_url:
        raise ValueError("Only GitHub repositories are allowed")

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(BASE_DIR, repo_name)

    # Remove old copy if exists (safe delete for Windows)
    delete_repo(repo_path)

    Repo.clone_from(repo_url, repo_path)
    return repo_path


# 🔹 Helper function to remove read-only files (Windows fix)
def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


# 🔹 Proper delete function (THIS is what your API should call)
def delete_repo(path: str):
    if os.path.exists(path):
        shutil.rmtree(path, onerror=remove_readonly)
