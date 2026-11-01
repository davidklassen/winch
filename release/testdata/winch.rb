cask "winch" do
  arch arm: "arm64", intel: "amd64"

  version "0.1.0"
  sha256 arm:   "2222222222222222222222222222222222222222222222222222222222222222",
         intel: "1111111111111111111111111111111111111111111111111111111111111111"

  url "https://github.com/davidklassen/winch/releases/download/v#{version}/winch-darwin-#{arch}.tar.gz"
  name "winch"
  desc "Server configuration tool"
  homepage "https://winchstack.app/"

  depends_on macos: :ventura

  binary "winch"
end
