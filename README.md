# resolvtrace

A lightweight Linux DNS observability tool built on libpcap and systemd.

## Install from source
```bash
sudo apt install libpcap-dev gcc make
make
sudo make install
sudo systemctl enable --now resolvtrace
```

## View logs
```bash
journalctl -u resolvtrace -f
tail -f /var/log/resolvtrace/resolvtrace.log
```

## License
MIT
# resolvtrace
