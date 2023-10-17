#include <algorithm>
#include <cstring>
#include <iostream>

#include "httpssession.h"

static ssize_t gnutls_pull_trampoline(gnutls_transport_ptr_t h, void *buf, size_t len)
{
    auto session = static_cast<HTTPSSession *>(h);
    return session->gnutls_pull(buf, len);
}

static ssize_t gnutls_push_trampoline(gnutls_transport_ptr_t h, const void *buf, size_t len)
{
    auto session = static_cast<HTTPSSession *>(h);
    return session->gnutls_push(buf, len);
}

HTTPSSession::HTTPSSession(std::shared_ptr<uvw::tcp_handle> handle,
    TCPSession::malformed_data_cb malformed_data_handler,
    TCPSession::got_dns_msg_cb got_dns_msg_handler,
    TCPSession::connection_ready_cb connection_ready_handler,
    handshake_error_cb handshake_error_handler,
    Target target,
    HTTPMethod method)
    : TCPSession(handle, malformed_data_handler, got_dns_msg_handler, connection_ready_handler)
    , http2_state{STATE_HTTP2::WAIT_SETTINGS}
    , _malformed_data{malformed_data_handler}
    , _got_dns_msg{got_dns_msg_handler}
    , _handle{handle}
    , _tls_state{LinkState::HANDSHAKE}
    , _handshake_error{handshake_error_handler}
    , _target{std::move(target)}
    , _method{method}
    , _current_session{nullptr}
{
}

HTTPSSession::~HTTPSSession()
{
    gnutls_certificate_free_credentials(_gnutls_cert_credentials);
    gnutls_deinit(_gnutls_session);
    nghttp2_session_del(_current_session);
}

std::unique_ptr<http2_stream_data> HTTPSSession::create_http2_stream_data(std::unique_ptr<char[]> data, size_t len)
{
    std::string uri = _target.uri;
    struct http_parser_url *u = _target.parsed;
    std::string scheme(&uri[u->field_data[UF_SCHEMA].off], u->field_data[UF_SCHEMA].len);
    std::string authority(&uri[u->field_data[UF_HOST].off], u->field_data[UF_HOST].len);
    std::string path(&uri[u->field_data[UF_PATH].off], u->field_data[UF_PATH].len);
    int32_t stream_id = -1;
    if (_method == HTTPMethod::GET) {
        path.append("?dns=");
        path.append(data.get(), len);
    }
    std::string streamData(data.get(), len);
    auto root = std::make_unique<http2_stream_data>(scheme, authority, path, stream_id, streamData);
    return root;
}
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

static ssize_t send_callback([[maybe_unused]] nghttp2_session *session, const uint8_t *data,
    size_t length, [[maybe_unused]] int flags, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    class_session->send_tls((void *)data, length);
    return (ssize_t)length;
}

void HTTPSSession::destroy_session()
{
    gnutls_certificate_free_credentials(_gnutls_cert_credentials);
    gnutls_deinit(_gnutls_session);
    nghttp2_session_del(_current_session);
}

void HTTPSSession::process_receive(const uint8_t *data, size_t len)
{
    // dnsheader is 12, at least one byte for the minimum name,
    // two bytes for the qtype and another two for the qclass
    const size_t MIN_DNS_RESPONSE_SIZE = 17;
    // 512 over UDP without EDNS, but 65535 over TCP
    const size_t MAX_DNS_RESPONSE_SIZE = 65535;
    if (len < MIN_DNS_RESPONSE_SIZE || len > MAX_DNS_RESPONSE_SIZE) {
        std::cerr << "malformed data" << std::endl;
        _malformed_data();
        return;
    }
    auto buf = std::make_unique<char[]>(len);
    memcpy(buf.get(), (const char *)data, len);
    _got_dns_msg(std::move(buf), len);
}

static int on_data_chunk_recv_callback(nghttp2_session *session, [[maybe_unused]] uint8_t flags,
    int32_t stream_id, const uint8_t *data,
    size_t len, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    auto req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!req) {
        std::cerr << "No stream data on data chunk" << std::endl;
        return 0;
    }
    auto existing = class_session->_recv_chunks.find(stream_id);
    if (existing != class_session->_recv_chunks.end()) {
        class_session->_recv_chunks[stream_id].insert(class_session->_recv_chunks[stream_id].end(), data, data + len);
    } else {
        class_session->_recv_chunks[stream_id] = std::vector<uint8_t>(data, data + len);
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, [[maybe_unused]] uint32_t error_code,
    [[maybe_unused]] void *user_data)
{
    auto stream_data = static_cast<http2_stream_data *>(nghttp2_session_get_stream_user_data(session, stream_id));
    if (!stream_data) {
        std::cerr << "No stream data on stream close" << std::endl;
        return 0;
    }
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    return 0;
}

int on_frame_recv_callback([[maybe_unused]] nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    switch (frame->hd.type) {
    case NGHTTP2_SETTINGS:
        class_session->settings_received();
        break;
    case NGHTTP2_DATA:
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            auto data = class_session->_recv_chunks[frame->data.hd.stream_id];
            class_session->process_receive(data.data(), data.size());
        }
    }
    return 0;
}

void HTTPSSession::init_nghttp2()
{
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_client_new(&_current_session, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
}

bool HTTPSSession::setup()
{
    int ret;

    ret = gnutls_init(&_gnutls_session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "GNUTLS init failed: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_set_default_priority(_gnutls_session);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "GNUTLS failed to set default priority: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_certificate_allocate_credentials(&_gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to allocate credentials: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_certificate_set_x509_system_trust(_gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to set system trust: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_credentials_set(_gnutls_session, GNUTLS_CRD_CERTIFICATE,
        _gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to set system credentials" << gnutls_strerror(ret) << std::endl;
        return false;
    }

    gnutls_datum_t alpn;
    alpn.data = (unsigned char *)"h2";
    alpn.size = 2;
    ret = gnutls_alpn_set_protocols(_gnutls_session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "GNUTLS failed to set ALPN: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    gnutls_transport_set_pull_function(_gnutls_session, gnutls_pull_trampoline);
    gnutls_transport_set_push_function(_gnutls_session, gnutls_push_trampoline);
    gnutls_handshake_set_timeout(_gnutls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    gnutls_transport_set_ptr(_gnutls_session, this);
    return true;
}

void HTTPSSession::send_settings()
{
    nghttp2_settings_entry settings[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, (1U << 31) - 1}};
    int val;
    val = nghttp2_submit_settings(_current_session, NGHTTP2_FLAG_NONE, settings, ARRLEN(settings));
    if (val != 0) {
        std::cerr << "Could not submit SETTINGS frame: " << nghttp2_strerror(val) << std::endl;
    }
}

void HTTPSSession::settings_received()
{
    if (http2_state == STATE_HTTP2::WAIT_SETTINGS) {
        TCPSession::on_connect_event();
        http2_state = STATE_HTTP2::SENDING_DATA;
    }
}

void HTTPSSession::receive_response(const char data[], size_t len)
{
    ssize_t stream_id = nghttp2_session_mem_recv(_current_session, (const uint8_t *)data, len);
    if (stream_id < 0) {
        std::cerr << "Could not get HTTP2 request: " << nghttp2_strerror(stream_id);
        close();
        return;
    }
}

int HTTPSSession::session_send()
{
    int rv;
    rv = nghttp2_session_send(_current_session);
    if (rv != 0) {
        std::cerr << "HTTP2 fatal error: " << nghttp2_strerror(rv);
        return -1;
    }
    return 0;
}

void HTTPSSession::on_connect_event()
{
    _current_session = {};
    do_handshake();
}

void HTTPSSession::close()
{
    _tls_state = LinkState::CLOSE;
    gnutls_bye(_gnutls_session, GNUTLS_SHUT_WR);
    TCPSession::close();
}

static ssize_t post_data(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, [[maybe_unused]] nghttp2_data_source *source, [[maybe_unused]] void *user_data)
{
    auto stream_data = static_cast<http2_stream_data *>(nghttp2_session_get_stream_user_data(session, stream_id));
    size_t nread = std::min(stream_data->data.size(), length);
    memcpy(buf, stream_data->data.c_str(), nread);
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return nread;
}

#define HDR_S(NAME, VALUE)                                                         \
    {                                                                              \
        (uint8_t *)NAME, (uint8_t *)VALUE.c_str(), sizeof(NAME) - 1, VALUE.size(), \
            NGHTTP2_NV_FLAG_NONE                                                   \
    }

void HTTPSSession::write(std::unique_ptr<char[]> data, size_t len)
{
    int32_t stream_id;
    auto stream_data = create_http2_stream_data(std::move(data), len);
    nghttp2_data_provider provider = {};

    std::string method = _method == HTTPMethod::GET ? "GET" : "POST";
    std::string content = "application/dns-message";
    std::vector<nghttp2_nv> hdrs{
        HDR_S(":method", method),
        HDR_S(":scheme", stream_data->scheme),
        HDR_S(":authority", stream_data->authority),
        HDR_S(":path", stream_data->path),
        HDR_S("accept", content)};
    if (_method == HTTPMethod::POST) {
        hdrs.push_back(HDR_S("content-type", content));
        hdrs.push_back(HDR_S("content-length", std::to_string(len)));
        provider.read_callback = post_data;
    }

    stream_id = nghttp2_submit_request(_current_session, NULL, hdrs.data(), hdrs.size(), &provider, stream_data.get());
    if (stream_id < 0) {
        std::cerr << "Could not submit HTTP request: " << nghttp2_strerror(stream_id);
    }

    stream_data->id = stream_id;

    if (session_send() != 0) {
        std::cerr << "HTTP2 failed to send" << std::endl;
    }
}

void HTTPSSession::receive_data(const char data[], size_t _len)
{
    _pull_buffer.append(data, _len);
    switch (_tls_state) {
    case LinkState::HANDSHAKE:
        do_handshake();
        break;
    case LinkState::DATA:
        char buf[16384];
        for (;;) {
            ssize_t len = gnutls_record_recv(_gnutls_session, buf, sizeof(buf));
            if (len > 0) {
                receive_response(buf, len);
            } else {
                if (len == GNUTLS_E_AGAIN) {
                    // Check if we don't have any data left to read
                    if (_pull_buffer.empty()) {
                        break;
                    }
                    continue;
                } else if (len == GNUTLS_E_INTERRUPTED) {
                    continue;
                }
                break;
            }
        }
        break;
    case LinkState::CLOSE:
        break;
    }
}

void HTTPSSession::send_tls(void *data, size_t len)
{
    ssize_t sent = gnutls_record_send(_gnutls_session, data, len);
    if (sent <= 0) {
        std::cerr << "HTTP2 failed in sending data" << std::endl;
    }
}

void HTTPSSession::do_handshake()
{
    int err = gnutls_handshake(_gnutls_session);
    if (err == GNUTLS_E_SUCCESS) {
        gnutls_datum_t alpn;
        alpn.data = (unsigned char *)"h2";
        alpn.size = 2;
        int ret = gnutls_alpn_get_selected_protocol(_gnutls_session, &alpn);
        if (ret != GNUTLS_E_SUCCESS) {
            std::cerr << "Cannot get alpn" << std::endl;
            close();
        }
        init_nghttp2();
        send_settings();
        if (session_send() != 0) {
            std::cerr << "Cannot submit settings frame" << std::endl;
        }
        _tls_state = LinkState::DATA;
    } else if (err < 0 && gnutls_error_is_fatal(err)) {
        std::cerr << "Handshake failed: " << gnutls_strerror(err) << std::endl;
        _handshake_error();
    } else if (err != GNUTLS_E_AGAIN && err != GNUTLS_E_INTERRUPTED) {
        std::cout << "Handshake " << gnutls_strerror(err) << std::endl;
    }
}

int HTTPSSession::gnutls_pull(void *buf, size_t len)
{
    if (!_pull_buffer.empty()) {
        len = std::min(len, _pull_buffer.size());
        std::memcpy(buf, _pull_buffer.data(), len);
        _pull_buffer.erase(0, len);
        return len;
    }
    errno = EAGAIN;
    return -1;
}

int HTTPSSession::gnutls_push(const void *buf, size_t len)
{
    auto data = std::make_unique<char[]>(len);
    memcpy(data.get(), const_cast<char *>(reinterpret_cast<const char *>(buf)), len);
    TCPSession::write(std::move(data), len);
    return len;
}
