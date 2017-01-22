#include <iostream>
#include <thread>
#include "CoapClient.h"
#include "CoapServer.h"

void test_coap_client(const std::string &host)
{
    printf("\n* Testing %s\n\n", host.c_str());

    CoapClient client(host);

    CoapClient::on_data_arrived.connect(
            [](unsigned char *data, size_t len)
            {
                printf("Data: %.*s\n", (int)len, data);
            });
    CoapClient::on_response_error.connect(
            [&](RESPONSE_CODE code)
            {
                printf("Response code received: %s\n", CoapResponseString::instance().get_string_for_code(code).c_str());
            });


    // INDEX GET (default constructor)
    client.prepare_request();
    client.send_request();

    // default GET
    client.set_resource("hello");
    client.prepare_request();
    client.send_request();

    // PUT hello before delete
    client.set_resource("hello");
    client.set_request_method(REQUEST::PUT);
    client.prepare_request();
    client.send_request();

    // DELETE hello
    client.set_resource("hello");
    client.set_request_method(REQUEST::DELETE);
    client.prepare_request();
    client.send_request();

    // GET hello after delete
    client.set_resource("hello");
    client.set_request_method(REQUEST::GET);
    client.prepare_request();
    client.send_request();

    // PUT hello after delete
    client.set_resource("hello");
    client.set_request_method(REQUEST::PUT);
    client.prepare_request();
    client.send_request();

    // GET hello after new PUT
    client.set_resource("hello");
    client.set_request_method(REQUEST::GET);
    client.prepare_request();
    client.send_request();

    // GET discover
    client.set_resource("discover");
    client.set_request_method(REQUEST::GET);
    client.prepare_request();
    client.send_request();

    // GET No valid resource
    client.set_resource("no-existo");
    client.set_request_method(REQUEST::GET);
    client.prepare_request();
    client.send_request();

    // GET large resource
    client.set_resource("large");
    client.set_request_method(REQUEST::GET);
    client.set_multiframe(true);
    client.prepare_request();
    client.send_request();
}

void test_coap_server()
{
    CoapServer server("localhost"); 

    server.start();

    // Wait for server start...
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    printf("Attemping to test clients...\n");
    test_coap_client("localhost");
}

int main(int argc, char **argv)
{
    std::cout << "\n\n**** Attemping to test COAP stuff...****\n\n";
    
    test_coap_server();

    std::cout << "Test finished" << std::endl;

    return 0;
}
