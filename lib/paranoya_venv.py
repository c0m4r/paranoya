"""
venv autodetect
"""

import os
import sys


def venv_setup(paranoya_venv_site: str) -> bool:
    """
    venv setup
    """
    if os.path.exists(paranoya_venv_site):
        sys.path.insert(0, paranoya_venv_site)
        return True
    return False


# venv detection
def venv_check(paranoya_script_name: str) -> None:
    """
    venv check
    """
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    paranoya_base_path = os.path.dirname(os.path.realpath(paranoya_script_name))
    paranoya_venv_path = f"{paranoya_base_path}/venv"
    paranoya_venv_site = (
        f"{paranoya_venv_path}/lib/python{python_version}/site-packages"
    )

    if not os.environ["PATH"].startswith(paranoya_venv_path):
        venv_ready = venv_setup(paranoya_venv_site)
        if not venv_ready:
            print(f"{paranoya_venv_path} not found")
            print("Consider using ./deploy.sh to deploy venv")
