# any_dns_dqy
** use it only on testing purposes **<br/>
** only A,AAAA,MX records are supported secured transport, other kinds are sent with normal dns requests. **

small dns server made with [any-dns](https://img.shields.io/crates/v/any-dns) service and [dqy](https://github.com/dandyvica/dqy) backend

```
# run doh transport dns proxy for A,AAAA,MX Records.
$ ./any_dns_dqy @https://cloudflare-dns.com/dns-query --doh
```

## todo
* doq thread problem
```
thread 'tokio-runtime-worker' panicked at .cargo\registry\src\index.crates.io-1949cf8c6b5b557f\tokio-1.45.1\src\runtime\scheduler\multi_thread\mod.rs:86:9:  
Cannot start a runtime from within a runtime. This happens because a function (like `block_on`) attempted to block the current thread while the thread is being used to drive asynchronous tasks.
```

