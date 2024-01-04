#!/bin/sh

if ! flatpak --version &> /dev/null; then echo "flatpak not found"; exit 1; fi
if ! flatpak-builder --version &> /dev/null; then echo "flatpak-builder not found"; exit 1; fi

flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
flatpak install org.freedesktop.Sdk//23.08 org.freedesktop.Platform//23.08
flatpak-builder --user --install --force-clean loki-daemonized-flatpak org.flatpak.Loki-daemonized.json
flatpak run org.flatpak.Loki-daemonized --intense -p ./test
