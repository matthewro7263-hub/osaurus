//
//  GlobalProxyConfigurationPortTests.swift
//  OsaurusNetworking
//

import XCTest

import OsaurusNetworking

final class GlobalProxyConfigurationPortTests: XCTestCase {

    /// `URLComponents` happily parses port 0 and ports above 65535, so without a
    /// range check the configuration accepted them and injected an invalid port
    /// into the CFNetwork proxy dictionary.
    func testRejectsZeroAndOutOfRangePorts() {
        for (url, expectedPort) in [
            ("http://proxy.example.com:0", 0),
            ("http://proxy.example.com:70000", 70000),
            ("http://proxy.example.com:99999", 99999),
        ] {
            XCTAssertThrowsError(try GlobalProxyConfiguration(urlString: url), "expected \(url) to be rejected") {
                error in
                XCTAssertEqual(
                    error as? GlobalProxyConfiguration.ValidationError,
                    .invalidPort(expectedPort),
                    "expected .invalidPort(\(expectedPort)) for \(url), got \(error)"
                )
            }
        }
    }

    /// Valid ports (including the 1 and 65535 boundaries) still construct.
    func testAcceptsInRangePorts() throws {
        for (url, expectedPort) in [
            ("http://proxy.example.com:1", 1),
            ("http://proxy.example.com:8080", 8080),
            ("socks://proxy.example.com:65535", 65535),
        ] {
            let config = try GlobalProxyConfiguration(urlString: url)
            XCTAssertEqual(config.port, expectedPort)
        }
    }

    /// The local-host guard only recognized native-form IPv6, so writing a
    /// loopback or link-local address in its IPv4-mapped (`::ffff:a.b.c.d`) or
    /// IPv4-compatible (`::a.b.c.d`) spelling walked straight past it.
    func testRejectsLocalAddressesEmbeddedInIPv6() {
        for url in [
            "socks://[::ffff:127.0.0.1]:1080",
            "http://[::ffff:127.1.2.3]:8080",
            "http://[::ffff:0.0.0.0]:8080",
            "http://[::ffff:169.254.1.1]:8080",
            "http://[::127.0.0.1]:8080",
            "http://[::169.254.1.1]:8080",
        ] {
            XCTAssertThrowsError(try GlobalProxyConfiguration(urlString: url), "expected \(url) to be rejected") {
                error in
                guard
                    let validation = error as? GlobalProxyConfiguration.ValidationError,
                    case .unsafeHost = validation
                else {
                    XCTFail("expected .unsafeHost for \(url), got \(error)")
                    return
                }
            }
        }
    }

    /// The embedded-IPv4 recheck must not over-block: routable addresses, and
    /// RFC1918 LAN proxies (allowed on purpose), still construct in v6 form.
    func testAcceptsNonLocalAddressesEmbeddedInIPv6() throws {
        for url in [
            "http://[::ffff:203.0.113.5]:8080",
            "http://[::ffff:192.168.1.1]:8080",
            "http://[::ffff:10.0.0.1]:8080",
        ] {
            let config = try GlobalProxyConfiguration(urlString: url)
            XCTAssertEqual(config.port, 8080, "expected \(url) to be accepted")
        }
    }

    /// Native-form IPv6 classification is unchanged by the embedded-IPv4 work.
    func testNativeIPv6ClassificationIsUnchanged() throws {
        for url in ["http://[::1]:8080", "http://[::]:8080", "http://[fe80::1]:8080"] {
            XCTAssertThrowsError(try GlobalProxyConfiguration(urlString: url), "expected \(url) to be rejected")
        }
        let config = try GlobalProxyConfiguration(urlString: "http://[2001:db8::1]:8080")
        XCTAssertEqual(config.port, 8080)
    }
}
