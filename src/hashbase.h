#pragma once

namespace crypto
{
    typedef unsigned char      u8;
    typedef unsigned short     u16;
    typedef unsigned int       u32;
    typedef unsigned long long u64;

    enum Result
    {
        Ok,
        UnknownFailure
    };

    template<typename t>
    using View = const t*;

    // Rotate value by n bits
    template<typename t>
    t rotl(t value, size_t n) 
    {
        constexpr t k = n % (sizeof(t) * 8);
        return (value << k) | (value >> ((sizeof(t) * 8) - k));
    }

    template<size_t n, typename t>
    t crotl(t value)
    {
        constexpr t k = n % (sizeof(t) * 8);
        return (value << k) | (value >> ((sizeof(t) * 8) - k));
    }

    template<typename t>
    t rotr(t value, size_t n)
    {
        t k = n % (sizeof(t) * 8);
        return (value >> k) | (value << ((sizeof(t) * 8) - k));
    }

    template<size_t n, typename t>
    t crotr(t value)
    {
        t k = n % (sizeof(t) * 8);
        return (value >> k) | (value << ((sizeof(t) * 8) - k));
    }

    template<size_t digestSize>
    class IHashFunction
    {
    public:
        virtual void operator()(const u8* message, const size_t& size, u8* digest) = 0;
        virtual void init() = 0;
        virtual void update(const u8* data, const size_t& size) = 0;
        virtual void final(u8* data) = 0;
        static constexpr size_t digestSizeBytes = digestSize / 8;
    private:
    protected:
    };

    class IExtendableOutputFunction
    {
    public:
        virtual void init() = 0;
        virtual void update(const u8* data, const size_t& size) = 0;
        virtual void final(u8* data, const size_t& outputSize) = 0;
    private:
    protected:
    };
}