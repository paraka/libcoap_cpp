#ifndef _COAP_COMMON_H_
#define _COAP_COMMON_H_

#include <sys/socket.h>
#include <map>
#include <string>

enum class PROTOCOL_VERSION
{
    IPV4,
    IPV6,
};

enum class REQUEST
{
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
};

enum class RESPONSE_CODE
{
    OK = 1,                         /* 2.00 OK */
    CREATED = 2,                    /* 2.01 Created */
    VALID = 3,                      /* 2.03 Valid */
    CHANGED = 4,                    /* 2.04 Changed */
    BAD_REQUEST = 5,                /* 4.00 Bad Request */
    NOT_FOUND = 6,                  /* 4.04 Not Found */
    METHOD_NOT_ALLOWED = 7,         /* 4.05 Method Not Allowed */
    UNSUPPORTED_MEDIA_TYPE = 8,     /* 4.15 Unsupported Media Type */
    INTERNAL_SERVER_ERROR = 9,      /* 5.00 Internal Server Error */
    NOT_IMPLEMENTED = 10,           /* 5.01 Not Implemented */
    SERVICE_UNAVAILABLE = 11,       /* 5.03 Service Unavailable */
    GATEWAY_TIMEOUT = 12,           /* 5.04 Gateway Timeout */
    INVALID_CODE = 13,
};


class CoapResponseString
{
public:
    ~CoapResponseString() = default;

    CoapResponseString(const CoapResponseString &other) = delete;
    CoapResponseString(const CoapResponseString &&other) = delete;
    CoapResponseString & operator= (const CoapResponseString &other) = delete;

    static CoapResponseString& instance()
    {
        static CoapResponseString instance;
        return instance;
    }

public:

    std::string get_string_for_code(RESPONSE_CODE code) const
    {
        const int tmp = static_cast<int>(code);
        
        if (tmp >= 1 && tmp < 12)
            return map_[code][1];

        throw std::runtime_error("Invalid response code!!");
    }

    RESPONSE_CODE get_code_for_string(const std::string &str, bool full_string = false) const
    {
        auto idx = (!full_string) ? 0 : 1;

        for (const auto &e : map_)
            if (e.second[idx] == str)
                return e.first;

        return RESPONSE_CODE::INVALID_CODE;
    }

private:

    CoapResponseString()
    {
        init_map();
    }

    void init_map()
    {
        std::array<std::string, 2> tmp { "2.00", "2.00 OK" };
        map_.insert(std::make_pair(RESPONSE_CODE::OK, tmp));
        tmp = { "2.01", "2.01 Created" };
        map_.insert(std::make_pair(RESPONSE_CODE::CREATED, tmp));
        tmp = { "2.03", "2.03 Valid" };
        map_.insert(std::make_pair(RESPONSE_CODE::VALID, tmp));
        tmp = { "2.04", "2.04 Changed" };
        map_.insert(std::make_pair(RESPONSE_CODE::CHANGED, tmp));
        tmp = { "4.00", "4.00 Bad Request" };
        map_.insert(std::make_pair(RESPONSE_CODE::BAD_REQUEST, tmp));
        tmp = { "4.04", "4.04 Not Found" };
        map_.insert(std::make_pair(RESPONSE_CODE::NOT_FOUND, tmp));
        tmp = { "4.05", "4.05 Method Not Allowed" };
        map_.insert(std::make_pair(RESPONSE_CODE::METHOD_NOT_ALLOWED, tmp));
        tmp = { "4.15", "4.05 Unsupported Media Type" };
        map_.insert(std::make_pair(RESPONSE_CODE::UNSUPPORTED_MEDIA_TYPE, tmp));
        tmp = { "5.00", "5.00 Internal Server Error" };
        map_.insert(std::make_pair(RESPONSE_CODE::INTERNAL_SERVER_ERROR, tmp));
        tmp = { "5.01", "5.01 Not Implemented" };
        map_.insert(std::make_pair(RESPONSE_CODE::NOT_IMPLEMENTED, tmp));
        tmp = { "5.03", "5.03 Service Unavailable" };
        map_.insert(std::make_pair(RESPONSE_CODE::SERVICE_UNAVAILABLE, tmp));
        tmp = { "5.04", "5.04 Gateway Timeout" };
        map_.insert(std::make_pair(RESPONSE_CODE::GATEWAY_TIMEOUT, tmp));
    }


private:
    mutable std::map<RESPONSE_CODE, std::array<std::string, 2>> map_;
};

class CoapCommon
{
    public:
        static inline unsigned short get_family_for_protocol_version(PROTOCOL_VERSION version)
        {
            return (version == PROTOCOL_VERSION::IPV4 ? AF_INET : AF_INET6);
        } 
};

#endif // _COAP_COMMON_H_
