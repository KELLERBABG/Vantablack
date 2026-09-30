# Homebrew Tap for Vantablack (`homebrew-vantablack`)

This tap allows macOS and Linux users to install Vantablack via Homebrew.

## User Installation

```bash
# Add this tap
brew tap KELLERBABG/vantablack

# Install Vantablack
brew install vantablack

# Or run as a background service
brew services start vantablack
```

## How to Set Up the GitHub Tap Repository

1. Create a new public GitHub repository named `homebrew-vantablack` under the `KELLERBABG` account:
   [https://github.com/new?name=homebrew-vantablack](https://github.com/new?name=homebrew-vantablack)
2. Push the `Formula/` directory into that repository:
   ```bash
   git clone https://github.com/KELLERBABG/homebrew-vantablack.git
   cd homebrew-vantablack
   # Copy Formula/vantablack.rb from packaging/homebrew/Formula/
   mkdir -p Formula
   cp /path/to/vantablack/packaging/homebrew/Formula/vantablack.rb Formula/
   git add Formula/vantablack.rb
   git commit -m "feat: initial Vantablack formula (v0.8.0)"
   git push origin main
   ```
3. Users can immediately install via `brew install KELLERBABG/vantablack/vantablack`!
