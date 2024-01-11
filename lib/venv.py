"""
Loki (daemonized) lib/venv.py
https://github.com/c0m4r/Loki-daemonized

Loki (daemonized): Simple IOC and YARA Scanner for Linux
Copyright (c) 2015-2023 Florian Roth
Copyright (c) 2023-2024 c0m4r

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
    else:
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
