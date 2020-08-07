Name
====

lua-resty-hyperscan - [Hyperscan](https://github.com/intel/hyperscan) for [Openresty](https://github.com/openresty/openresty)

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
  * [init](#init)
  * [hs_block_compile](#hs_block_compile)
  * [hs_block_scan](#hs_block_scan)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

This library is under development so far.

Description
===========

**THIS LIBRARY ONLY SUPPORT [BLOCK SCAN](http://intel.github.io/hyperscan/dev-reference/api_files.html#c.HS_MODE_BLOCK) NOW !**

**THIS LIBRARY IS NOT THREAD-SAFE !**

Synopsis
========

```lua
init_by_lua_block {
    local hs = require('hyperscan')

    -- load the shared libary and check the CPU
    local ret, err = hs.init(hs.HS_WORK_MODE_NORMAL)
    if not ret then
        return ngx.log(ngx.ERR, "hyperscan init failed, ", err)
    end

    -- a set of patterns, should load from file or Redis
    local patterns = {
        {id = 1001, pattern = "\\d3",       flag = hs.HS_FLAG_CASELESS},
        {id = 1002, pattern = "\\s{3,5}",   flag = 0},
        {id = 1003, pattern = "[a-d]{2,7}", flag = 0}
    }

    -- compile patterns to a database
    ret, err = hs.hs_block_compile(patterns)
    if not ret then
        return ngx.log(ngx.ERR, "hyperscan block compile failed, ", err)
    end
}


location / {
    content_by_lua_block {
        local hs = require('hyperscan')
        local mret, id, from, to = hs.hs_block_scan('0000000ABCD000000000abcd1122')
        if mret then
            return ngx.say("match:", id, "  ", from, "-", to)
        end

        return ngx.say("not match")
    }
}
```

[Back to TOC](#table-of-contents)

Methods
=======

[Back to TOC](#table-of-contents)

init
---

`syntax: db, err = mysql:new()`

Creates a MySQL connection object. In case of failures, returns `nil` and a string describing the error.

[Back to TOC](#table-of-contents)

hs_block_compile
-------

`syntax: ok, err, errcode, sqlstate = db:connect(options)`

Attempts to connect to the remote MySQL server.

The `options` argument is a Lua table holding the following keys:

* `host`
  
    the host name for the MySQL server.

* `port`
  
    the port that the MySQL server is listening on. Default to 3306.

* `path`
  
    the path of the unix socket file listened by the MySQL server.

* `database`
  
    the MySQL database name.

* `user`
  
    MySQL account name for login.

* `password`
  
    MySQL account password for login (in clear text).

* `charset`
  
    the character set used on the MySQL connection, which can be different from the default charset setting.
  The following values are accepted: `big5`, `dec8`, `cp850`, `hp8`, `koi8r`, `latin1`, `latin2`,
  `swe7`, `ascii`, `ujis`, `sjis`, `hebrew`, `tis620`, `euckr`, `koi8u`, `gb2312`, `greek`,
  `cp1250`, `gbk`, `latin5`, `armscii8`, `utf8`, `ucs2`, `cp866`, `keybcs2`, `macce`,
  `macroman`, `cp852`, `latin7`, `utf8mb4`, `cp1251`, `utf16`, `utf16le`, `cp1256`,
  `cp1257`, `utf32`, `binary`, `geostd8`, `cp932`, `eucjpms`, `gb18030`.

* `max_packet_size`
  
    the upper limit for the reply packets sent from the MySQL server (default to 1MB).

* `ssl`
  
    If set to `true`, then uses SSL to connect to MySQL (default to `false`). If the MySQL
    server does not have SSL support
    (or just disabled), the error string "ssl disabled on server" will be returned.

* `ssl_verify`
  
    If set to `true`, then verifies the validity of the server SSL certificate (default to `false`).
    Note that you need to configure the [lua_ssl_trusted_certificate](https://github.com/openresty/lua-nginx-module#lua_ssl_trusted_certificate)
    to specify the CA (or server) certificate used by your MySQL server. You may also
    need to configure [lua_ssl_verify_depth](https://github.com/openresty/lua-nginx-module#lua_ssl_verify_depth)
    accordingly.

* `pool`
  
    the name for the MySQL connection pool. if omitted, an ambiguous pool name will be generated automatically with the string template `user:database:host:port` or `user:database:path`. (this option was first introduced in `v0.08`.)

* `pool_size`
  
    Specifies the size of the connection pool. If omitted and no `backlog` option was provided, no pool will be created. If omitted but `backlog` was provided, the pool will be created with a default size equal to the value of the [lua_socket_pool_size](https://github.com/openresty/lua-nginx-module#lua_socket_pool_size) directive. The connection pool holds up to `pool_size` alive connections ready to be reused by subsequent calls to [connect](#connect), but note that there is no upper limit to the total number of opened connections outside of the pool. If you need to restrict the total number of opened connections, specify the `backlog` option. When the connection pool would exceed its size limit, the least recently used (kept-alive) connection already in the pool will be closed to make room for the current connection. Note that the cosocket connection pool is per Nginx worker process rather than per Nginx server instance, so the size limit specified here also applies to every single Nginx worker process. Also note that the size of the connection pool cannot be changed once it has been created. Note that at least [ngx_lua 0.10.14](https://github.com/openresty/lua-nginx-module/tags) is required to use this options.

* `backlog`
  
    If specified, this module will limit the total number of opened connections for this pool. No more connections than `pool_size` can be opened for this pool at any time. If the connection pool is full, subsequent connect operations will be queued into a queue equal to this option's value (the "backlog" queue). If the number of queued connect operations is equal to `backlog`, subsequent connect operations will fail and return nil plus the error string `"too many waiting connect operations"`. The queued connect operations will be resumed once the number of connections in the pool is less than `pool_size`. The queued connect operation will abort once they have been queued for more than `connect_timeout`, controlled by [set_timeout](#set_timeout), and will return nil plus the error string "timeout". Note that at least [ngx_lua 0.10.14](https://github.com/openresty/lua-nginx-module/tags) is required to use this options.

* `compact_arrays`
  
    when this option is set to true, then the [query](#query) and [read_result](#read_result) methods will return the array-of-arrays structure for the resultset, rather than the default array-of-hashes structure.

Before actually resolving the host name and connecting to the remote backend, this method will always look up the connection pool for matched idle connections created by previous calls of this method.

[Back to TOC](#table-of-contents)

hs_block_scan
----------

`syntax: hs.hs_block_scan(string)`

Sets the timeout (in ms) protection for subsequent operations, including the `connect` method.

[Back to TOC](#table-of-contents)

Author
======

Lubin <lgbxyz@gmail.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the MIT license.

[Back to TOC](#table-of-contents)

See Also
========

* the ngx_lua module: https://github.com/openresty/lua-nginx-module
* the MySQL wired protocol specification: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol
* the [lua-resty-memcached](https://github.com/agentzh/lua-resty-memcached) library
* the [lua-resty-redis](https://github.com/agentzh/lua-resty-redis) library
* the ngx_drizzle module: https://github.com/openresty/drizzle-nginx-module

[Back to TOC](#table-of-contents)
