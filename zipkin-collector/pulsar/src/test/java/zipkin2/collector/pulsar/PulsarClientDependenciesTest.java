/*
 * Copyright The OpenZipkin Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package zipkin2.collector.pulsar;

import org.apache.pulsar.shade.io.airlift.compress.lz4.Lz4Decompressor;
import org.apache.pulsar.shade.io.netty.channel.ChannelHandlerContext;
import org.apache.pulsar.shade.io.netty.channel.ChannelPromise;
import org.apache.pulsar.shade.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.DefaultDnsQuestion;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.DefaultDnsQuery;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.DnsOpCode;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.DnsRecordType;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.DnsSection;
import org.apache.pulsar.shade.io.netty.handler.codec.dns.TcpDnsQueryEncoder;
import org.apache.pulsar.shade.io.netty.handler.codec.http.DefaultHttpHeaders;
import org.apache.pulsar.shade.io.netty.handler.proxy.HttpProxyHandler;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * pulsar-client shades its dependencies, relocating them under {@code org.apache.pulsar.shade}.
 * Scanners that rely on Maven metadata therefore cannot see them, so a stale pulsar-client can
 * silently reintroduce known vulnerabilities. These tests exercise the shaded code directly and
 * fail if it regresses to a vulnerable version.
 *
 * @see <a href="https://github.com/openzipkin/zipkin/issues/3839">issue #3839</a>
 */
class PulsarClientDependenciesTest {

  /** io.airlift:aircompressor before 2.0.3, CVE-2025-67721. */
  @Test void shadedLz4DecompressorRejectsZeroMatchOffset() {
    // The first match has an offset of zero, which reads back into the reused output buffer
    byte[] compressed = {15, 0, 0, -1, -1, -118, 49, -1, -1, 0};
    byte[] decompressed = new byte[1024];

    assertThatThrownBy(() -> new Lz4Decompressor().decompress(compressed, 0, compressed.length,
      decompressed, 0, decompressed.length))
      .hasMessageContaining("offset outside destination buffer");
  }

  /** io.netty:netty-codec-dns before 4.1.133.Final, CVE-2026-42579. */
  @Test void shadedDnsCodecRejectsNullBytesInLabels() {
    DefaultDnsQuery query = new DefaultDnsQuery(1, DnsOpCode.QUERY);
    query.addRecord(DnsSection.QUESTION,
      new DefaultDnsQuestion("evil\0.example.com", DnsRecordType.A));

    EmbeddedChannel channel = new EmbeddedChannel(new TcpDnsQueryEncoder());
    try {
      assertThatThrownBy(() -> channel.writeOutbound(query))
        .hasStackTraceContaining("DNS label contains null byte");
    } finally {
      channel.finishAndReleaseAll();
    }
  }

  /** io.netty:netty-handler-proxy before 4.1.133.Final, CVE-2026-42578. */
  @Test void shadedHttpProxyHandlerRejectsInjectedHeaders() throws Exception {
    // Without validation, the CRLF smuggles an extra header into the CONNECT request
    HttpProxyHandler handler = new HttpProxyHandler(new InetSocketAddress("127.0.0.1", 8080),
      new DefaultHttpHeaders(false).add("X-Test", "value\r\nInjected: true"), false);
    handler.setConnectTimeoutMillis(0); // avoids scheduling a timeout on the mocked context

    ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
    handler.connect(ctx, new InetSocketAddress("10.0.0.1", 8080), null, mock(ChannelPromise.class));

    // channelActive sends the CONNECT request, which is where the headers are validated
    assertThatThrownBy(() -> handler.channelActive(ctx))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("Validation failed for header 'X-Test'");
  }
}
