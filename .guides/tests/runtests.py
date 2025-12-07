#!/usr/bin/env python3
import os
import sys
import pygit2
import shutil
from pathlib import Path


# Get the students' github username and name of repository
def clone_student_repo():
    try:
        credentials_folder = "/home/codio/workspace/student_credentials"
        with open(credentials_folder, "r") as f:
            github_username, DIR = f.readlines()
            github_username, DIR = github_username.strip(), DIR.strip()
    except Exception as e:
        print("Error: could not open credentials folder")
        print(f"Make sure the folder \"{credentials_folder}\" exists")
        sys.exit(1)

    # Clear any existing directory (clone_respository will fail otherwise)
    # dir_string = f'/home/codio/workspace/.guides/student_code/{DIR}'
    dir_path = Path('/home/codio/workspace/.guides/student_code') / DIR
    try:
        if dir_path.exists():
            shutil.rmtree(dir_path)
    except OSError as e:
        print("Error when removing directory: %s : %s" % (os.fspath(dir_path), e.strerror))

    key_dir = Path("/home/codio/workspace/ssh_keys")
    key_file = key_dir / "id_mcit5830"
    pub_key = key_dir / "id_mcit5830.pub"

    if not key_file.is_file() or not pub_key.is_file():
        print(f"Error can't find SSH keys!")
        print(f"Make sure \"{os.fspath(key_file)}\" and \"{os.fspath(pub_key)}\" exist")
        sys.exit(1)

    try:
        # import student code using pygit2
        keypair = pygit2.Keypair("git", os.fspath(pub_key), os.fspath(key_file), "")
        callbacks = pygit2.RemoteCallbacks(credentials=keypair)
        print(f'Cloning from: git@github.com:{github_username}/{DIR}.git')
        pygit2.clone_repository(f"git@github.com:{github_username}/{DIR}.git",
                                os.fspath(dir_path),
                                callbacks=callbacks)
        sys.path.append(os.fspath(dir_path))
    except:
        print("Failed to clone the repository.")
        sys.exit(1)

    return dir_path


def main():
    try:
        from validate import validate
    except ImportError:
        raise ImportError("Unable import validation script")

    if Path(__file__).name != 'runtests_local.py':
        code_path = clone_student_repo()
    else:
        print(f"Running tests locally (no git clone)")
        code_path = Path("/home/codio/workspace")

    # Execute the test on the student's code
    sys.path.append(os.fspath(code_path))
    grade = validate(code_path)

    if Path(__file__).name == 'autograde.py':
        # Send the grade back to Codio
        CODIO_AUTOGRADE_URL = os.environ["CODIO_AUTOGRADE_URL"]
        CODIO_UNIT_DATA = os.environ["CODIO_AUTOGRADE_ENV"]
        # import grade submit function
        sys.path.append('/usr/share/codio/assessments')
        from lib.grade import send_grade
        res = send_grade(int(round(grade)))
        sys.exit(0)
    if Path(__file__).name == 'runtests.py' or Path(__file__).name == 'runtests_local.py':
        print(f"Score would be {grade}%")
        sys.exit(0)
    print(f"Unknown file name -- please contact your instructor")
    print(f"Score would be {grade}%")


main()
