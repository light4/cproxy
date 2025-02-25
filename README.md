<p align="center">
<img width="250px" src="https://user-images.githubusercontent.com/18649508/139117888-4f631b07-0b40-4d24-b478-fb805ceef689.png" />
</p>
<hr/>

Forked from <https://github.com/NOBLES5E/cproxy>

- support config ~/.config/cproxy/config.kdl
- support ipv6
- update iptables and iproute2 mods

[![CI](https://github.com/light4/cproxy/actions/workflows/test.yaml/badge.svg)](https://github.com/light4/cproxy/actions/workflows/test.yaml)
[![build-and-release](https://github.com/light4/cproxy/actions/workflows/build-and-release.yaml/badge.svg)](https://github.com/light4/cproxy/actions/workflows/build-and-release.yaml)

`cproxy` can redirect TCP and UDP traffic made by a program to a proxy, without requiring the program supporting a
proxy.

What you can achieve with `cproxy`: All the things listed on for
example [V2Ray Guide](https://guide.v2fly.org/en_US/app/app.html), including advanced configurations like reverse proxy
for NAT traversal, and you can **apply different proxy on different applications**.

Compared to many existing complicated transparent proxy setup, `cproxy` usage is as easy as `proxychains`, but
unlike `proxychains`, it works on any program (including static linked Go programs) and redirects DNS requests.

Note: The proxy used by `cproxy` should be a transparent proxy port (such as V2Ray's `dokodemo-door` inbound and
shadowsocks `ss-redir`). A good news is that even if you only have a SOCKS5 or HTTP proxy, there are tools that can
convert it to a transparent proxy for you (for example, [transocks](https://github.com/cybozu-go/transocks)
, [ipt2socks](https://github.com/zfl9/ipt2socks) and [ip2socks-go](https://github.com/lcdbin/ip2socks-go)).

## Installation

You can install by downloading the binary from the [release page](https://github.com/NOBLES5E/cproxy/releases) or
install with `cargo`:

```
cargo install cproxy
chown root:root $(which cproxy) && chmod +s $(which cproxy)
```

## Usage

### Simple usage: just like `proxychains`

You can launch a new program with `cproxy` with:

```
cproxy --port <destination-local-port> -- <your-program> --arg1 --arg2 ...
```

All TCP connections requests will be proxied. If your local transparent proxy support DNS address overriding, you can
also redirect DNS traffic with `--redirect-dns`:

```
cproxy --port <destination-local-port> --redirect-dns -- <your-program> --arg1 --arg2 ...
```

For an example setup, see [wiki](https://github.com/NOBLES5E/cproxy/wiki/Example-setup-with-V2Ray).

### Simple usage: use iptables tproxy

If your system support `tproxy`, you can use `tproxy` with `--mode tproxy`:

```bash
cproxy --port <destination-local-port> --mode tproxy -- <your-program> --arg1 --arg2 ...
# or for existing process
cproxy --port <destination-local-port> --mode tproxy --pid <existing-process-pid>
```

With `--mode tproxy`, there are several differences:

- All UDP traffic are proxied instead of only DNS UDP traffic to port 53.
- Your V2Ray or shadowsocks service should have `tproxy` enabled on the inbound port. For V2Ray, you
  need `"tproxy": "tproxy"` as
  in [V2Ray Documentation](https://www.v2ray.com/en/configuration/transport.html#sockoptobject). For shadowsocks, you
  need `-u` as shown in [shadowsocks manpage](http://manpages.org/ss-redir).

An example setup can be found [here](https://github.com/NOBLES5E/cproxy/wiki/Example-setup-with-V2Ray).

Note that when you are using the `tproxy` mode, you can override the DNS server address
with `cproxy --mode tproxy --override-dns <your-dns-server-addr> ...`. This is useful when you want to use a different
DNS server for a specific application.

### Advanced usage: proxy an existing process

With `cproxy`, you can even proxy an existing process. This is very handy when you want to proxy existing system
services such as `docker`. To do this, just run

```
cproxy --port <destination-local-port> --pid <existing-process-pid>
```

The target process will be proxied as long as this `cproxy` command is running. You can press Ctrl-C to stop proxying.

### Advanced usage: debug a program's network activity with iptables LOG target

With `cproxy`, you can easily debug a program's traffic in netfilter. Just run the program with

```bash
cproxy --mode trace <your-program>
```

You will be able to see log in `dmesg`. Note that this requires a recent enough kernel and iptables.

## How does it work?

`cproxy` creates a unique `cgroup` for the proxied program, and redirect its traffic with packet rules.

## Limitations

- `cproxy` requires root access to modify `cgroup`.
- Currently only tested on Linux.

## Similar projects

There are some awesome existing work:

- [graftcp](https://github.com/hmgle/graftcp): work on most programs, but cannot proxy UDP (such as DNS)
  requests. `graftcp` also has performance hit on the underlying program, since it uses `ptrace`.
- [proxychains](https://github.com/haad/proxychains): easy to use, but not working on static linked programs (such as Go
  programs).
- [proxychains-ng](https://github.com/rofl0r/proxychains-ng): similar to proxychains.
- [cgproxy](https://github.com/springzfx/cgproxy): `cgproxy` also uses cgroup to do transparent proxy, and the idea is
  similar to `cproxy`'s. There are some differences in UX and system requirements:
  - `cgproxy` requires system `cgroup` v2 support, while `cproxy` works with both v1 and v2.
  - `cgproxy` requires a background daemon process `cgproxyd` running, while `cproxy` does not.
  - `cgproxy` requires `tproxy`, which is optional in `cproxy`.
  - `cgproxy` can be used to do global proxy, while `cproxy` does not intended to support global proxy.

### Reference

mod [src/iptables](./src/iptables.rs) forked from <https://github.com/yaa110/rust-iptables>
