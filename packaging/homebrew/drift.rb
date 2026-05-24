# Homebrew formula skeleton for drift.
#
# When the project ships its first release this file lives in a tap repo
# (e.g. github.com/sufforest/homebrew-tap/Formula/drift.rb). Until then
# it documents the intended layout. Replace the placeholder url + sha256
# values with the real release artefacts at tag time.
class Drift < Formula
  desc "End-to-end encrypted workspaces on your own S3-compatible bucket"
  homepage "https://github.com/sufforest/drift"
  url "https://github.com/sufforest/drift/releases/download/v0.0.0/drift-0.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "TBD"

  depends_on "rclone"

  # macFUSE is a cask, not a formula, so we can't `depends_on` it
  # directly. The post-install caveat below tells users to install it
  # when they want mount-mode vols.

  def install
    bin.install "drift"
    man1.install "drift.1" if File.exist?("drift.1")
  end

  def caveats
    <<~EOS
      drift uses rclone for the data plane (installed alongside) and
      FUSE for mount-mode vols.

      macOS users: install macFUSE separately to mount workspaces.
        brew install --cask macfuse
        (reboot + approve under System Settings → Privacy & Security)

      Linux users: install fuse3 from your distro's package manager.

      Sync-mode vols work without FUSE.

      To enable storing keys in the macOS Keychain (recommended):
        export DRIFT_KEYCHAIN=1
    EOS
  end

  test do
    assert_match "drift", shell_output("#{bin}/drift --help")
    assert_match version.to_s, shell_output("#{bin}/drift --version")
  end
end
