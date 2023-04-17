
def common_suites(expect):
    expect("**/openresty/nginx/sbin/nginx", "nginx rpath should contain kong lib") \
        .rpath.equals("/usr/local/openresty/luajit/lib:/usr/local/kong/lib")

    expect("**/openresty/nginx/sbin/nginx", "nginx binary should contain dwarf info for dynatrace") \
        .has_dwarf_info.equals(True) \
        .has_ngx_http_request_t_DW.equals(True)

    expect("**/openresty/nginx/sbin/nginx", "nginx binary should link pcre statically") \
        .exported_symbols.contains("pcre_free") \
        .needed_libraries.does_not().contain_match("libpcre.so.+")

    expect("**/openresty/nginx/sbin/nginx", "nginx compiled with OpenSSL 1.1.1") \
        .nginx_compiled_openssl.matches("OpenSSL 1.1.1.+") \
        .needed_libraries.does_not().contain_match("libpcre.so.+") \
        .version_requirement.key("libssl.so.1.1").is_not().greater_than("OPENSSL_1_1_1") \
        .version_requirement.key("libcrypto.so.1.1").is_not().greater_than("OPENSSL_1_1_1") \


def libc_libcpp_suites(expect, max_libc: str, max_libcpp: str):
    if max_libc:
        expect("**/*.so", "libc version is less than %s" % max_libc) \
            .version_requirement.key("libc.so.6").is_not().greater_than("GLIBC_%s" % max_libc) \
            .version_requirement.key("libdl.so.2").is_not().greater_than("GLIBC_%s" % max_libc) \
            .version_requirement.key("libpthread.so.0").is_not().greater_than("GLIBC_%s" % max_libc) \
            .version_requirement.key("librt.so.1").is_not().greater_than("GLIBC_%s" % max_libc) \

    if max_libcpp:
        expect("**/*.so", "libc version is less than %s" % max_libcpp) \
            .version_requirement.key("libstdc++.so.6").is_not().greater_than("GLIBCXX_%s" % max_libcpp)

def arm64_suites(expect):
    expect("**/lib/lua/5.1/**.so", "Lua C library uses aarch64 ld") \
        .needed_libraries.contain("ld-linux-aarch64.so.1")

    expect("**/kong/lib/**.so", "Lua FFI library uses aarch64 ld") \
        .needed_libraries.contain("ld-linux-aarch64.so.1")

    expect("**/openresty/nginx/sbin/nginx", "Nginx uses aarch64 ld") \
        .needed_libraries.contain("ld-linux-aarch64.so.1")