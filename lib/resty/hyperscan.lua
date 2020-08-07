

local ffi = require('ffi')
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local nkeys = require('table.nkeys')

local string_gmatch = string.gmatch
local string_match = string.match

local _M = {
    _VERSION = '0.1.0',
    _HS_VER  = '5.3.0', -- Hyperscan v5.3.0
    -- compiler pattern flags
    HS_FLAG_CASELESS     = 1,
    HS_FLAG_DOTALL       = 2,
    HS_FLAG_MULTILINE    = 4,
    HS_FLAG_SINGLEMATCH  = 8,
    HS_FLAG_ALLOWEMPTY   = 16,
    HS_FLAG_UTF8         = 32,
    HS_FLAG_UCP          = 64,
    HS_FLAG_PREFILTER    = 128,
    HS_FLAG_SOM_LEFTMOST = 256,
    HS_FLAG_COMBINATION  = 512,
    HS_FLAG_QUIET        = 1024,
    -- work mode
    HS_WORK_MODE_NORMAL       = 1, -- both Compilation and Scanning, use libhs.so
    HS_WORK_MODE_ONLY_RUNTIME = 2, -- only Scanning, use libhs_runtime.so, http://intel.github.io/hyperscan/dev-reference/serialization.html
}

--local mt = { __index = _M }
--setmetatable(_M, mt)

ffi.cdef[[
enum {
    HS_SUCCESS             = 0,
    HS_INVALID             = (-1),
    HS_NOMEM               = (-2),
    HS_SCAN_TERMINATED     = (-3),
    HS_COMPILER_ERROR      = (-4),
    HS_DB_VERSION_ERROR    = (-5),
    HS_DB_PLATFORM_ERROR   = (-6),
    HS_DB_MODE_ERROR       = (-7),
    HS_BAD_ALIGN           = (-8),
    HS_BAD_ALLOC           = (-9),
    HS_SCRATCH_IN_USE      = (-10),
    HS_ARCH_ERROR          = (-11),
    HS_INSUFFICIENT_SPACE  = (-12),
    HS_UNKNOWN_ERROR       = (-13)
};

/* Compiler mode flag */
enum {
    HS_MODE_BLOCK        =  1,
    HS_MODE_STREAM       =  2,
    HS_MODE_VECTORED     =  4
};

typedef struct hs_database {
    char* dummy;
} hs_database_t;

typedef struct hs_scratch {
    char* dummy;
} hs_scratch_t;

typedef struct hs_platform_info {
    unsigned int tune;
    unsigned long long cpu_features;
    unsigned long long reserved1;
    unsigned long long reserved2;
} hs_platform_info_t;

typedef struct hs_compile_error {
    char* message;
    int   expression;
} hs_compile_error_t;

typedef struct hs_expr_ext {
    unsigned long long flags;
    unsigned long long min_offset;
    unsigned long long max_offset;
    unsigned long long min_length;
    unsigned edit_distance;
    unsigned hamming_distance;
} hs_expr_ext_t;

/*----------------- Compile Regular Expression  -----------------*/
int hs_free_database(hs_database_t *db);
int hs_free_compile_error(hs_compile_error_t *error);
int hs_valid_platform(void);
int hs_database_info(const hs_database_t *database, char **info);
int hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);
int hs_free_scratch(hs_scratch_t *scratch);

/* CallBack function */
typedef int (*match_event_handler)(
    unsigned int id,
    unsigned long long from,
    unsigned long long to,
    unsigned int flags,
    void *context);

/*----------------- Compile Regular Expression  -----------------*/
int hs_compile_ext_multi(
    const char *const *expressions,
    const unsigned int *flags,
    const unsigned int *ids,
    const hs_expr_ext_t *const *ext,
    unsigned int elements, 
    unsigned int mode,
    const hs_platform_info_t *platform,
    hs_database_t **db, 
    hs_compile_error_t **error);

/* Block Scan */
int hs_scan(
    const hs_database_t *db, 
    const char *data,
    unsigned int length, 
    unsigned int flags,
    hs_scratch_t *scratch, 
    match_event_handler onEvent,
    void *context);

/*--------------- Compile Pure Literals -----------------*/

/*--------------- Database Serialization ----------------*/
int hs_deserialize_database(const char *bytes, const size_t length, hs_database_t **db);
int hs_deserialize_database_at(const char *bytes, const size_t length, hs_database_t *db);
int hs_serialized_database_size(const char *bytes, const size_t length, size_t *deserialized_size);
]]


local hyperscan    = nil
local hs_datebase  = ffi_new('hs_database_t*[1]')
local hs_scratch   = ffi_new('hs_scratch_t*[1]')
local hs_result    = {id=0, from=0, to=0}
local hs_init_mode = _M.HS_WORK_MODE_NORMAL

local function _find_shared_obj(so_name)
    for k,_ in string_gmatch(package.cpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        if so_path then
            so_path = so_path .. so_name
            local f = io.open(so_path)
            if f ~= nil then
                io.close(f)
                return so_path
            end
        end
    end
end

function _M.init(mode, serialization_db_path)
    mode = mode or _M.HS_WORK_MODE_NORMAL
    -- check OS --TODO
    -- check hyperscan shared library
    local so_name = 'libhs.so.' .. _M._HS_VER
    if mode == _M.HS_WORK_MODE_ONLY_RUNTIME then
        so_name = 'libhs_runtime.so.' .. _M._HS_VER
    end
    local so_path = _find_shared_obj(so_name)
    if so_path ~= nil then
        hyperscan = ffi.load(so_path)
        hs_init_mode = mode
    else
        return false, so_name .. " shared library not found !"
    end

    -- check CPU Instruction Set
    local ret = hyperscan.hs_valid_platform()
    if ret ~= hyperscan.HS_SUCCESS then
        return false, "CPU Not Support SSSE3 Instruction !"
    end

    -- load db from file in runtime mode
    if mode == _M.HS_WORK_MODE_ONLY_RUNTIME then
        if not serialization_db_path then
            return false, "Please specify serialization datebase path !"
        end
        local file = io.open(serialization_db_path, "rb")
        if not file then
            return false, "Please specify serialization datebase path !"
        end
        local db_data = file:read("a")
        local db_size = file:seek()
        ret = hyperscan.hs_deserialize_database(db_data, db_size, hs_datebase)

    end

    return true, "load " .. so_path .. " success !"
end

local function _hs_compile_internal(patterns, mode)
    -- env Check
    if not hyperscan then
        return false, "should call init() first !"
    end
    if hs_init_mode ~= _M.HS_WORK_MODE_NORMAL then
        return false, "runtime work mode not support Compilation !"
    end

    -- Parameter Check
    local count = nkeys(patterns)
    if count < 1 then
        return false, "No Patterns !"
    end

    local expressions = ffi_new('char*[?]', count)
    local ids         = ffi_new('unsigned int[?]', count)
    local flags       = ffi_new('unsigned int[?]', count)

    local index = 0
    for _,v in pairs(patterns) do
        ids[index]         = v.id
        flags[index]       = v.flag
        expressions[index] = ffi_cast('char*', v.pattern)
        index = index + 1
    end

    local hserr = ffi_new('hs_compile_error_t*[1]')

    local ret = hyperscan.hs_compile_ext_multi(
        ffi_cast('const char* const*', expressions),  -- const char *const *expressions,
        flags,           -- const unsigned int *flags,
        ids,             -- const unsigned int *ids,
        nil,             -- const hs_expr_ext_t *const *ext,
        count,           -- unsigned int elements,
        mode,            -- unsigned int mode,
        nil,             -- const hs_platform_info_t *platform,
        hs_datebase,     --hs_database_t **db,
        hserr            --hs_compile_error_t **error
    )
    if ret ~= hyperscan.HS_SUCCESS then
        local errlog = hserr.message
        hyperscan.hs_free_compile_error(hserr[0])
        return false, errlog
    end

    if mode ~= hyperscan.HS_MODE_STREAM then
        -- alloc scratch space
        ret = hyperscan.hs_alloc_scratch(hs_datebase[0], hs_scratch)
        if ret ~= hyperscan.HS_SUCCESS then
            hyperscan.hs_free_database(hs_datebase[0])
            return false, "alloc scratch failed, ret = " .. ret
        end
    end

    return true, "ok"
end


function _M.hs_block_compile(patterns)
    return _hs_compile_internal(patterns, hyperscan.HS_MODE_BLOCK)
end

--[[
function _M.hs_stream_compile(patterns)
    return _hs_compile_internal(patterns, hyperscan.HS_MODE_STREAM)
end

function _M.hs_vector_compile(patterns)
    return _hs_compile_internal(patterns, hyperscan.HS_MODE_VECTORED)
end
--]]

-- CallBack
local function hs_match_event_handler(id, from, to, flag, context)
    hs_result.id   = tonumber(id)
    hs_result.from = tonumber(from)
    hs_result.to   = tonumber(to)
    return 1
end

function _M.hs_block_scan(string)
    local ret = hyperscan.hs_scan(
        hs_datebase[0],         -- const hs_database_t *,
        string,                 -- const char *data,
        string.len(string),     -- unsigned int length,
        0,                      -- unsigned int flags,
        hs_scratch[0],          -- hs_scratch_t *scratch,
        hs_match_event_handler, -- match_event_handler onEvent,
        nil                     -- void *context
    )

    if ret == hyperscan.HS_SCAN_TERMINATED then
        return true, hs_result.id, hs_result.from, hs_result.to
    end

    return false
end

--[[
-- return a stream id
function _M.hs_stream_scan_start()
    local hs_stream   = ffi_new('hs_stream_t*[1]')
end

function _M.hs_stream_scan_work(stream_id, data)
end

function _M.hs_stream_scan_end(stream_id)
end

function _M.hs_vector_scan()
end
--]]

return _M
