"""
venv autodetect
"""

import os
import sys


def venv_setup(loki_venv_site: str) -> bool:
    """
    venv setup
    """
    if os.path.exists(loki_venv_site):
        sys.path.insert(0, loki_venv_site)
        return True
    return False


# venv detection
def venv_check(loki_script_name: str) -> None:
    """
    venv check
    """
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    loki_base_path = os.path.dirname(os.path.realpath(loki_script_name))
    loki_venv_path = f"{loki_base_path}/venv"
    loki_venv_site = f"{loki_venv_path}/lib/python{python_version}/site-packages"

    if not os.environ["PATH"].startswith(loki_venv_path):
        venv_ready = venv_setup(loki_venv_site)
        if not venv_ready:
            print(f"{loki_venv_path} not found")
            print("Consider using ./deploy.sh to deploy venv")
