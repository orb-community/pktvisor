
#include "DnstapInputStream.h"
#include <catch2/catch.hpp>

using namespace visor::input::dnstap;

// bidirectional: READY with dnstap content-type
static uint8_t bi_frame_1_len42[] = {
    0x00, 0x00, 0x00, 0x00, // escape: expect control frame
    0x00, 0x00, 0x00, 0x22, // control frame length 0x22 == 34 bytes
    // control frame 34 bytes
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x70, 0x72, 0x6f, 0x74,
    0x6f, 0x62, 0x75, 0x66, 0x3a, 0x64, 0x6e, 0x73, 0x74, 0x61, 0x70, 0x2e, 0x44, 0x6e, 0x73, 0x74,
    0x61, 0x70};

struct MockClient {
    void write(std::unique_ptr<char[]> data, unsigned int len)
    {
    }
};

TEST_CASE("bi-directional frame stream process", "[dnstap][frmstrm]")
{
    auto on_data_frame = [](const void *data, std::size_t len_data) {
        WARN("data frame parsed");
    };

    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, on_data_frame);
    CHECK_NOTHROW(session.receive_socket_data(bi_frame_1_len42, 42));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Ready);
    CHECK(session.is_bidir() == true);
}

TEST_CASE("dnstap file", "[dnstap][file]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    stream.start();
    stream.stop();
}

TEST_CASE("dnstap socket", "[dnstap][socket]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", "/tmp/dnstap-test.sock");

    stream.start();
    stream.stop();
}
