# Arch Linux AUR Package (`vantablack-bin`)

## How to Publish to the Arch User Repository (AUR)

1. Register an account on [https://aur.archlinux.org/](https://aur.archlinux.org/) and add your public SSH key in Account Settings.
2. Clone the AUR repository:
   ```bash
   git clone ssh://aur@aur.archlinux.org/vantablack-bin.git
   cd vantablack-bin
   ```
3. Copy `PKGBUILD`, `vantablack.service`, and `vantablack.desktop` from this directory into the cloned repo.
4. Generate the `.SRCINFO` metadata file:
   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```
5. Commit and push:
   ```bash
   git add PKGBUILD .SRCINFO vantablack.service vantablack.desktop
   git commit -m "release: update to v0.8.0"
   git push origin master
   ```
6. Anyone on Arch Linux, Manjaro, or EndeavourOS can now run:
   ```bash
   yay -S vantablack-bin
   # or
   paru -S vantablack-bin
   ```
