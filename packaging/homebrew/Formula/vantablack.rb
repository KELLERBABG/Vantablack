class Vantablack < Formula
  desc "Autonomous Post-Quantum WAN Mesh Routing Daemon & Serverless Sharding VPN"
  homepage "https://vantablack.kellersystems.dev"
  version "0.8.0"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/KELLERBABG/Vantablack/releases/download/v0.8.0/ggn-v0.8.0-aarch64-apple-darwin.tar.gz"
      # sha256 will be updated once release assets are finalized
    else
      url "https://github.com/KELLERBABG/Vantablack/releases/download/v0.8.0/ggn-v0.8.0-x86_64-apple-darwin.tar.gz"
    end
  elsif OS.linux?
    url "https://github.com/KELLERBABG/Vantablack/releases/download/v0.8.0/ggn-v0.8.0-x86_64-unknown-linux-gnu.tar.gz"
  end

  def install
    bin.install "ggn" => "vantablack"
    bin.install "ggn"
    if File.exist?("ggn-headless")
      bin.install "ggn-headless"
    end
  end

  service do
    run [opt_bin/"vantablack"]
    keep_alive true
    log_path var/"log/vantablack.log"
    error_log_path var/"log/vantablack.err.log"
  end

  test do
    assert_match "Vantablack", shell_output("#{bin}/vantablack --version 2>&1", 1)
  end
end
