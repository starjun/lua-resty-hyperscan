Name
====

lua-resty-hyperscan - [Hyperscan](https://github.com/intel/hyperscan) for [Openresty](https://github.com/openresty/openresty)

Table of Contents
=================

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Status](#status)
- [Description](#description)
- [Synopsis](#synopsis)
- [Methods](#methods)
  - [load library](#load-library)
  - [init](#init)
  - [hs_block_compile](#hs_block_compile)
  - [hs_block_scan](#hs_block_scan)
- [Author](#author)
- [Copyright and License](#copyright-and-license)
- [See Also](#see-also)

Status
======

This library is under development so far.

Description
===========

**THIS LIBRARY ONLY SUPPORT [BLOCK SCAN](http://intel.github.io/hyperscan/dev-reference/api_files.html#c.HS_MODE_BLOCK) NOW !**

**THIS LIBRARY IS NOT THREAD-SAFE !**

**THIS LIBRARY IS ONLY TESTED on CentOS 7 !**

# Dependency

You should build the hyperscan shared library. I got some pre-build blow:

- [CentOS 7](https://github.com/LubinLew/lua-resty-hyperscan/tree/master/hslibs/el7_x64)

- [CentOS 8](https://github.com/LubinLew/lua-resty-hyperscan/tree/master/hslibs/el8_x64)

- [MacOS](https://github.com/LubinLew/lua-resty-hyperscan/tree/master/hslibs/osx)

- [Windows 10](https://github.com/LubinLew/lua-resty-hyperscan/tree/master/hslibs/win10_x64)

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
    default_type text/plain;
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

way to load this library

```lua
local hs = require('hyperscan')
```

init
----

```lua
local ok, err = hs.init(mode [,serialized_db_path])
```

Load Hyperscan shared library and check the CPU Instruction Set.

### Parameters

#### `mode`

- hs.`HS_WORK_MODE_NORMAL`    work well now
- hs.`HS_WORK_MODE_RUNTIME`  do not work now, I don't know why ...

#### `serialized_db_path`

if parameter `mode`  is hs.`HS_WORK_MODE_RUNTIME`, then this parameter is necessary.

### Return Value

#### `ok`

boolean value. true for success, false for failure and check ther `err`.

#### `err`

string value to indicate error. 

[Back to TOC](#table-of-contents)

hs_block_compile
----------------

```lua
local ret, err = hs.hs_block_compile(patterns)
```

Compile patterns to a datebase for block mode scanning.

### Parameters

#### `patterns`

regex table.

### Return Value

#### `ok`

boolean value. true for success, false for failure and check ther `err`.

#### `err`

string value to indicate error.

[Back to TOC](#table-of-contents)

hs_block_scan
-------------

```lua
local ret, id, from, to = hs.hs_block_scan(string)
```

scan the input data and return the match result

### Parameters

#### `string`

a string.

### Return Value

#### `ret`

boolean value.

#### `id`

matched id.

#### `from` , `to`

matched postion.

[Back to TOC](#table-of-contents)

Author
======

Lubin <lgbxyz@gmail.com>.

Copyright and License
=====================

This module is licensed under the MIT license.

See Also
========

* Hyperscan Developer’s Reference Guide: http://intel.github.io/hyperscan/dev-reference/

[Back to TOC](#table-of-contents)
