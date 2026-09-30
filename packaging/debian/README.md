# Debian / Ubuntu Packaging (`.deb`)

## Generating `.deb` Packages with `cargo-deb`

To build an installable `.deb` package directly:

```bash
# 1. Install cargo-deb
cargo install cargo-deb

# 2. Build the package
cargo deb --bin ggn
```

The resulting package will be placed in `target/debian/vantablack_0.8.0_amd64.deb`.

## Installing the `.deb` Package

```bash
sudo dpkg -i target/debian/vantablack_0.8.0_amd64.deb
# If dependencies are missing:
sudo apt-get install -f
```
