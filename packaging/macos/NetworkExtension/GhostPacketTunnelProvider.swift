import NetworkExtension

/// Production NetworkExtension boundary.
///
/// The Rust core remains entitlement-free. The containing app must pass an
/// authenticated control socket or approved App Group handle to the core; this
/// provider owns only Apple's lifecycle and packet-flow descriptors.
final class GhostPacketTunnelProvider: NEPacketTunnelProvider {
    private var session: GhostTunnelSession?

    override func startTunnel(options: [String : NSObject]?,
                               completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.66.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.66.0.10"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["10.66.0.1"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self, error == nil else {
                completionHandler(error)
                return
            }
            do {
                self.session = try GhostTunnelSession(packetFlow: self.packetFlow)
                try self.session?.start()
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        session?.stop()
        session = nil
        completionHandler()
    }
}

/// Narrow FFI seam. The implementation is intentionally supplied by the signed
/// host application so the extension never invents a second packet format.
private final class GhostTunnelSession {
    private let packetFlow: NEPacketTunnelFlow
    init(packetFlow: NEPacketTunnelFlow) { self.packetFlow = packetFlow }
    func start() throws { /* bind to the Rust VpnIngress/TunDevice bridge */ }
    func stop() { }
}
